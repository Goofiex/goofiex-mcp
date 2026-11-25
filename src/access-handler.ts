import { verifyAccessIdToken } from "./oidc-verify.mjs";
import { canonicalOrigin, callbackState, stateCookie, clearStateCookie, readApprovalForm } from "./browser-flow.mjs";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import {
	addApprovedClient,
	createOAuthState,
	fetchUpstreamAuthToken,
	generateCSRFProtection,
	getUpstreamAuthorizeUrl,
	isClientApproved,
	OAuthError,
	type Props,
	renderApprovalDialog,
	validateCSRFToken,
	validateOAuthState,
} from "./workers-oauth-utils";

type EnvWithOauth = Cloudflare.Env & { OAUTH_PROVIDER: OAuthHelpers };

export async function handleAccessRequest(
	request: Request,
	env: EnvWithOauth,
	_ctx: ExecutionContext,
) {
	const { pathname, searchParams } = new URL(request.url);
	try {
		const origin = canonicalOrigin(env.MCP_RESOURCE, request.url);

		if (request.method === "GET" && pathname === "/authorize") {
			const oauthReqInfo = await env.OAUTH_PROVIDER.parseAuthRequest(request);
			const { clientId } = oauthReqInfo;
			if (!clientId) {
				return new Response("Invalid request", { status: 400 });
			}

			// Check if client is already approved — no approval form so no CSRF cookie to clear
			if (await isClientApproved(request, clientId, env.COOKIE_ENCRYPTION_KEY)) {
				const { stateToken, codeChallenge } = await createOAuthState(
					oauthReqInfo,
					env.OAUTH_KV,
					env.COOKIE_ENCRYPTION_KEY,
				);
				return redirectToAccess(origin, env, stateToken, codeChallenge);
			}

			// Generate CSRF protection for the approval form
			const { token: csrfToken, setCookie } = generateCSRFProtection();
			// The browser receives a random handle, never authority to change the parsed OAuth request.
			await env.OAUTH_KV.put(`oauth:approval:${csrfToken}`, JSON.stringify(oauthReqInfo), { expirationTtl: 600 });

			return renderApprovalDialog(request, {
				client: await env.OAUTH_PROVIDER.lookupClient(clientId),
				csrfToken,
				server: {
					description: "This is a demo MCP Remote Server using Access for authentication.",
					logo: "https://avatars.githubusercontent.com/u/314135?s=200&v=4",
					name: "Cloudflare Access MCP Server",
				},
				setCookie,
				state: {},
			});
		}

		if (request.method === "POST" && pathname === "/authorize") {
			try {
				const formData = await readApprovalForm(request, origin);
				const csrfResult = validateCSRFToken(formData, request);
				const csrfToken = formData.get("csrf_token") as string;
				const approvalKey = `oauth:approval:${csrfToken}`;
				const stored = await env.OAUTH_KV.get(approvalKey);
				if (!stored) return new Response("Invalid or expired approval", { status: 400 });
				const oauthReqInfo = JSON.parse(stored) as AuthRequest;
				if (!oauthReqInfo.clientId) return new Response("Invalid approval", { status: 400 });
				await env.OAUTH_KV.delete(approvalKey);

				// Add client to approved list
				const approvedClientCookie = await addApprovedClient(
					request,
					oauthReqInfo.clientId,
					env.COOKIE_ENCRYPTION_KEY,
				);

				// Create OAuth state
				const { stateToken, codeChallenge } = await createOAuthState(
					oauthReqInfo,
					env.OAUTH_KV,
					env.COOKIE_ENCRYPTION_KEY,
				);

				// Build redirect headers — use Headers to support multiple Set-Cookie values
				const redirectHeaders = new Headers();
				redirectHeaders.append("Set-Cookie", approvedClientCookie);
				redirectHeaders.append("Set-Cookie", csrfResult.clearCookie);

				return redirectToAccess(origin, env, stateToken, codeChallenge, redirectHeaders);
			} catch {
				return new Response("Authorization failed", { status: 400, headers: { "Cache-Control": "no-store" } });
			}
		}

		if (request.method === "GET" && pathname === "/callback") {
			// Validate OAuth state (retrieves stored data from KV)
			let oauthReqInfo: AuthRequest;
			let codeVerifier: string;

			try {
				callbackState(request);
				const result = await validateOAuthState(
					request,
					env.OAUTH_KV,
					env.COOKIE_ENCRYPTION_KEY,
				);
				oauthReqInfo = result.oauthReqInfo;
				codeVerifier = result.codeVerifier;
			} catch (error: any) {
				if (error instanceof OAuthError) {
					return error.toResponse();
				}
				// Unexpected non-OAuth error
				return new Response("Authorization failed", { status: 400, headers: { "Cache-Control": "no-store" } });
			}

			if (!oauthReqInfo.clientId) {
				return new Response("Invalid OAuth request data", { status: 400 });
			}

			// Exchange the code for an access token, including the PKCE verifier
			const [, idToken, errResponse] = await fetchUpstreamAuthToken({
				client_id: env.ACCESS_CLIENT_ID,
				client_secret: env.ACCESS_CLIENT_SECRET,
				code: searchParams.get("code") ?? undefined,
				redirect_uri: new URL("/callback", origin).href,
				upstream_url: env.ACCESS_TOKEN_URL,
				code_verifier: codeVerifier,
			});
			if (errResponse) {
				return errResponse;
			}

			const idTokenClaims = await verifyAccessIdToken(idToken, {
				issuer: env.ACCESS_ISSUER,
				clientId: env.ACCESS_CLIENT_ID,
				jwksUrl: env.ACCESS_JWKS_URL,
			});
			const user = {
				email: idTokenClaims.email,
				emailVerified: idTokenClaims.emailVerified,
				name: idTokenClaims.name,
				sub: idTokenClaims.sub,
			};

			// Return back to the MCP client a new token
			const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
				metadata: {
					label: user.name,
				},
				// This will be available through getMcpAuthContext() in MCP handlers.
				props: {
					email: user.email,
					emailVerified: user.emailVerified,
					login: user.sub,
					name: user.name,
				} as Props,
				request: oauthReqInfo,
				scope: oauthReqInfo.scope,
				userId: user.sub,
			});

			return new Response(null, { status: 302, headers: { Location: redirectTo, "Set-Cookie": clearStateCookie(), "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
		}

		return new Response("Not Found", { status: 404 });
	} catch {
		return new Response("Authorization failed", { status: 400, headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
	}
}

async function redirectToAccess(
	origin: string,
	env: Env,
	stateToken: string,
	codeChallenge: string,
	extraHeaders: Headers = new Headers(),
) {
	const headers = new Headers(extraHeaders);
	headers.append("Set-Cookie", stateCookie(stateToken));
	headers.set("Cache-Control", "no-store");
	headers.set("Referrer-Policy", "no-referrer");
	headers.set(
		"location",
		getUpstreamAuthorizeUrl({
			client_id: env.ACCESS_CLIENT_ID,
			code_challenge: codeChallenge,
			redirect_uri: new URL("/callback", origin).href,
			scope: "openid email profile",
			state: stateToken,
			upstream_url: env.ACCESS_AUTHORIZATION_URL,
		}),
	);
	return new Response(null, { headers, status: 302 });
}
