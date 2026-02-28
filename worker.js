const supportedProviders = ["github"];

const htmlHeaders = {
	"Content-Type": "text/html;charset=UTF-8",
	"Cache-Control": "no-store",
};

const jsonHeaders = {
	"Content-Type": "application/json;charset=UTF-8",
	"Cache-Control": "no-store",
};

const escapeRegExp = (str) => str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const escapeHtml = (str) => str.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");

const parseCookie = (request) => {
	const cookie = request.headers.get("Cookie") ?? "";
	return Object.fromEntries(
		cookie
			.split(/;\s*/)
			.map((pair) => pair.trim())
			.filter(Boolean)
			.map((pair) => {
				const i = pair.indexOf("=");
				if (i < 0) return [pair, ""];
				return [pair.slice(0, i), pair.slice(i + 1)];
			}),
	);
};

const decodeJSON = async (request) => {
	try {
		return await request.json();
	} catch {
		return null;
	}
};

const outputHTML = ({ provider = "unknown", token, error, errorCode }) => {
	const state = error ? "error" : "success";
	const content = error ? { provider, error, errorCode } : { provider, token };
	const headers = new Headers(htmlHeaders);
	headers.append("Set-Cookie", "cms-auth-csrf=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure");
	headers.append("Set-Cookie", "cms-auth-oauth-state=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure");

	return new Response(
		`
      <!doctype html><html><body><script>
        (() => {
          window.addEventListener('message', ({ data, origin }) => {
            if (data === 'authorizing:${provider}') {
              window.opener?.postMessage(
                'authorization:${provider}:${state}:${JSON.stringify(content)}',
                origin
              );
            }
          });
          window.opener?.postMessage('authorizing:${provider}', '*');
        })();
      </script></body></html>
    `,
		{ headers },
	);
};

const unauthorized = (message) =>
	new Response(JSON.stringify({ ok: false, error: message }), {
		status: 401,
		headers: jsonHeaders,
	});

const badRequest = (message) =>
	new Response(JSON.stringify({ ok: false, error: message }), {
		status: 400,
		headers: jsonHeaders,
	});

const toLowerList = (value) =>
	(value ?? "")
		.split(",")
		.map((entry) => entry.trim().toLowerCase())
		.filter(Boolean);

const isDomainAllowed = (domain, env) => {
	const list = env.ALLOWED_DOMAINS;
	if (!list) return true;
	return list.split(",").some((pattern) => (domain ?? "").match(new RegExp(`^${escapeRegExp(pattern.trim()).replace("\\*", ".+")}$`)));
};

const isAllowedGoogleEmail = (email, env) => {
	const allowlist = toLowerList(env.ALLOWED_GOOGLE_EMAILS);
	if (!allowlist.length) return false;
	return allowlist.includes(email.toLowerCase());
};

const isAllowedGitHubLogin = (login, env) => {
	const allowlist = toLowerList(env.ALLOWED_GITHUB_LOGINS);
	if (!allowlist.length) return false;
	return allowlist.includes(String(login ?? "").toLowerCase());
};

const isAllowedGitHubEmail = (email, env) => {
	const allowlist = toLowerList(env.ALLOWED_GITHUB_EMAILS);
	if (!allowlist.length) return false;
	return allowlist.includes(String(email ?? "").toLowerCase());
};

const parsePasswordUsers = (raw) => {
	if (!raw) return new Map();
	const text = raw.trim();

	if (!text) return new Map();

	const normalizeSecret = (secret) => {
		const value = String(secret ?? "").trim();
		if (!value) return null;
		if (value.toLowerCase().startsWith("plain:")) {
			const plain = value.slice(6);
			return plain ? { type: "plain", value: plain } : null;
		}
		if (/^[a-f0-9]{64}$/i.test(value)) {
			return { type: "hash", value: value.toLowerCase() };
		}
		return { type: "plain", value };
	};

	const entriesToMap = (entries) => new Map(entries.map(([email, secret]) => [String(email).toLowerCase(), normalizeSecret(secret)]).filter(([email, parsed]) => email && parsed));

	try {
		if (text.startsWith("{")) {
			const parsed = JSON.parse(text);
			return entriesToMap(Object.entries(parsed));
		}

		if (text.startsWith("[")) {
			const parsed = JSON.parse(text);
			return entriesToMap(parsed.filter((item) => item?.email && (item?.passwordSha256 || item?.password)).map((item) => [item.email, item.passwordSha256 ?? item.password]));
		}
	} catch {
		return new Map();
	}

	return entriesToMap(
		text
			.split(",")
			.map((entry) => entry.trim())
			.filter(Boolean)
			.map((pair) => {
				const i = pair.indexOf(":");
				if (i < 0) return [pair, ""];
				return [pair.slice(0, i), pair.slice(i + 1)];
			}),
	);
};

const sha256Hex = async (value) => {
	const bytes = new TextEncoder().encode(value);
	const hash = await crypto.subtle.digest("SHA-256", bytes);
	return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
};

const getProvider = (url) => {
	const { searchParams } = new URL(url);
	return searchParams.get("provider") ?? "github";
};

const verifyGoogleIdToken = async (idToken, env) => {
	let response;
	try {
		const params = new URLSearchParams({ id_token: idToken });
		response = await fetch(`https://oauth2.googleapis.com/tokeninfo?${params}`);
	} catch {
		return { ok: false, error: "Could not verify Google token." };
	}

	if (!response?.ok) {
		return { ok: false, error: "Google token was rejected." };
	}

	const data = await response.json();
	const issuers = new Set(["accounts.google.com", "https://accounts.google.com"]);
	const allowedAudience = new Set(toLowerList(env.GOOGLE_CLIENT_IDS || env.GOOGLE_CLIENT_ID));

	if (!issuers.has(data.iss)) {
		return { ok: false, error: "Invalid Google token issuer." };
	}
	if (!allowedAudience.size || !allowedAudience.has(String(data.aud).toLowerCase())) {
		return { ok: false, error: "Google token audience mismatch." };
	}
	if (String(data.email_verified) !== "true") {
		return { ok: false, error: "Google email is not verified." };
	}
	if (!data.email || !isAllowedGoogleEmail(data.email, env)) {
		return { ok: false, error: "Google account is not in the allowlist." };
	}

	return { ok: true, email: String(data.email).toLowerCase() };
};

const renderAuthPage = (provider, csrfToken, env) => {
	const googleClientId = env.GOOGLE_CLIENT_ID ?? "";
	const googleEnabled = Boolean(googleClientId);
	const googleScript = googleEnabled ? `<script src="https://accounts.google.com/gsi/client" async defer></script>` : "";
	const githubOauthEnabled = Boolean(env.GITHUB_OAUTH_CLIENT_ID && env.GITHUB_OAUTH_CLIENT_SECRET);
	const githubButton = githubOauthEnabled ? `<button id="githubOAuthButton" type="button" class="oauth-btn github">GitHub</button>` : "";
	const googleButton =
		googleEnabled ?
			`
      <div class="google-wrap">
        <div id="googleSignInButton" class="google-button"></div>
      </div>
    `
		:	"";
	const oauthSection =
		githubButton || googleButton ?
			`
    <div class="oauth-group">
      ${githubButton}
      ${googleButton}
    </div>
    `
		:	"";

	return new Response(
		`
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CMS Authentication</title>
  ${googleScript}
  <style>
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px; font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: linear-gradient(160deg, #f6f7fb 0%, #eceff6 100%); color: #111827; }
    .wrap { width: min(360px, 100%); background: rgba(255, 255, 255, .94); border-radius: 20px; padding: 28px; box-shadow: 0 28px 70px rgba(15, 23, 42, .10); border: 1px solid rgba(148, 163, 184, .22); backdrop-filter: blur(18px); }
    h1 { margin: 0 0 20px; font-size: 1rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: #334155; }
    form { display: grid; gap: 12px; }
    input { width: 100%; border: 1px solid #d7deea; border-radius: 14px; padding: 14px 15px; font-size: 15px; transition: border-color .15s ease, box-shadow .15s ease, transform .15s ease; background: #fff; color: #111827; }
    input::placeholder { color: #94a3b8; }
    input:focus { outline: none; border-color: #0f172a; box-shadow: 0 0 0 4px rgba(15, 23, 42, .08); transform: translateY(-1px); }
    button { width: 100%; border: none; border-radius: 14px; padding: 14px 15px; font-size: 15px; font-weight: 700; cursor: pointer; transition: transform .12s ease, box-shadow .15s ease, opacity .15s ease; }
    button:hover { transform: translateY(-1px); }
    button:active { transform: translateY(0); }
    button:disabled { cursor: default; opacity: .7; transform: none; }
    button[type="submit"] { margin-top: 4px; background: #0f172a; color: #fff; box-shadow: 0 14px 28px rgba(15, 23, 42, .18); }
    .oauth-group { margin-top: 14px; display: grid; gap: 10px; }
    .oauth-btn { background: #fff; color: #111827; border: 1px solid #d7deea; box-shadow: 0 10px 22px rgba(148, 163, 184, .14); }
    .oauth-btn.github { background: #111827; color: #fff; border-color: #111827; box-shadow: 0 14px 28px rgba(17, 24, 39, .18); }
    .google-wrap { width: 100%; min-height: 44px; }
    .google-button { width: 100%; min-height: 44px; }
    #status { margin-top: 12px; min-height: 20px; font-size: 13px; text-align: center; }
    .error { color: #b91c1c; }
    .ok { color: #047857; }
    .muted { color: #64748b; }
    @media (max-width: 480px) {
      body { padding: 16px; }
      .wrap { padding: 22px; border-radius: 18px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Sign in</h1>

    <form id="emailForm">
      <input id="email" name="email" type="email" autocomplete="username" placeholder="Email" required />
      <input id="password" name="password" type="password" autocomplete="current-password" placeholder="Password" required />
      <button type="submit">Sign in</button>
    </form>
    ${oauthSection}
    <div id="status" class="muted"></div>
  </div>

	  <script>
	    const csrfToken = ${JSON.stringify(csrfToken)};
	    const provider = ${JSON.stringify(provider)};
	    const googleClientId = ${JSON.stringify(googleClientId)};
	    const githubOAuthEnabled = ${JSON.stringify(githubOauthEnabled)};
	    const statusEl = document.getElementById("status");

    const setStatus = (text, kind = "muted") => {
      statusEl.textContent = text;
      statusEl.className = kind;
    };

    document.getElementById("emailForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = new FormData(event.currentTarget);
      setStatus("Signing in...", "muted");
      const response = await fetch("/auth/email", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider,
          csrfToken,
          email: form.get("email"),
          password: form.get("password"),
        }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        setStatus(body.error || "Email sign-in failed.", "error");
        return;
      }

      document.open();
      document.write(await response.text());
      document.close();
    });

	    document.getElementById("githubOAuthButton")?.addEventListener("click", () => {
	      if (!githubOAuthEnabled) return;
	      setStatus("Redirecting to GitHub...", "muted");
	      const params = new URLSearchParams({ provider, csrfToken });
	      window.location.href = "/auth/github/start?" + params.toString();
	    });

	    window.onGoogleCredentialResponse = async (googleResponse) => {
	      setStatus("Verifying Google sign-in...", "muted");
	      const response = await fetch("/auth/google", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider,
          csrfToken,
          credential: googleResponse.credential,
        }),
      });

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        setStatus(body.error || "Google sign-in failed.", "error");
        return;
      }

	      document.open();
	      document.write(await response.text());
	      document.close();
	    };

	    let resizeTimer;
	    let googleInitialized = false;

	    const renderGoogleButton = () => {
	      if (!googleClientId) return;
	      const container = document.getElementById("googleSignInButton");
	      if (!container) return;
	      if (!window.google?.accounts?.id) return;

	      if (!googleInitialized) {
	        window.google.accounts.id.initialize({
	          client_id: googleClientId,
	          callback: window.onGoogleCredentialResponse,
	          auto_select: false,
	          cancel_on_tap_outside: true,
	        });
	        googleInitialized = true;
	      }

	      const width = Math.max(220, Math.floor(container.clientWidth));
	      container.innerHTML = "";
	      window.google.accounts.id.renderButton(container, {
	        type: "standard",
	        theme: "outline",
	        size: "large",
	        text: "continue_with",
	        shape: "rectangular",
	        width,
	        logo_alignment: "left",
	      });
	    };

	    const initGoogleButton = () => {
	      if (!googleClientId) return;
	      if (window.google?.accounts?.id) {
	        renderGoogleButton();
	        window.addEventListener("resize", () => {
	          clearTimeout(resizeTimer);
	          resizeTimer = setTimeout(renderGoogleButton, 120);
	        });
	        return;
	      }
	      setTimeout(initGoogleButton, 120);
	    };

	    initGoogleButton();
	  </script>
</body>
</html>`,
		{ headers: htmlHeaders },
	);
};

const handleAuth = async (request, env) => {
	const { url } = request;
	const { searchParams } = new URL(url);
	const provider = getProvider(url);
	const domain = searchParams.get("site_id");

	if (!supportedProviders.includes(provider)) {
		return outputHTML({
			provider,
			error: "Unsupported Git backend provider.",
			errorCode: "UNSUPPORTED_BACKEND",
		});
	}
	if (!isDomainAllowed(domain, env)) {
		return outputHTML({
			provider,
			error: "Domain is not allowlisted.",
			errorCode: "UNSUPPORTED_DOMAIN",
		});
	}
	if (!env.GITHUB_PAT) {
		return outputHTML({
			provider,
			error: "Server is misconfigured. Missing GitHub PAT.",
			errorCode: "MISCONFIGURED_GITHUB_PAT",
		});
	}

	const csrfToken = crypto.randomUUID().replaceAll("-", "");
	return new Response(renderAuthPage(provider, csrfToken, env).body, {
		headers: {
			...htmlHeaders,
			"Set-Cookie": `cms-auth-csrf=${csrfToken}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
		},
	});
};

const verifyCsrf = (request, csrfToken) => {
	const cookies = parseCookie(request);
	return Boolean(csrfToken && cookies["cms-auth-csrf"] && cookies["cms-auth-csrf"] === csrfToken);
};

const handleEmailAuth = async (request, env) => {
	const body = await decodeJSON(request);
	if (!body) return badRequest("Invalid request payload.");

	const provider = String(body.provider ?? "github");
	if (!supportedProviders.includes(provider)) return badRequest("Unsupported provider.");
	if (!verifyCsrf(request, String(body.csrfToken ?? ""))) return unauthorized("Session expired.");

	const email = String(body.email ?? "")
		.trim()
		.toLowerCase();
	const password = String(body.password ?? "");
	if (!email || !password) return badRequest("Email and password are required.");

	const users = parsePasswordUsers(env.EMAIL_PASSWORD_USERS);
	const expectedSecret = users.get(email);
	if (!expectedSecret) return unauthorized("Email is not allowlisted for password login.");

	const inputHash = await sha256Hex(password);
	const expectedHash = expectedSecret.type === "hash" ? expectedSecret.value : await sha256Hex(expectedSecret.value);
	if (inputHash !== expectedHash) return unauthorized("Invalid email/password.");

	return outputHTML({ provider, token: env.GITHUB_PAT });
};

const handleGoogleAuth = async (request, env) => {
	const body = await decodeJSON(request);
	if (!body) return badRequest("Invalid request payload.");

	const provider = String(body.provider ?? "github");
	if (!supportedProviders.includes(provider)) return badRequest("Unsupported provider.");
	if (!verifyCsrf(request, String(body.csrfToken ?? ""))) return unauthorized("Session expired.");

	const credential = String(body.credential ?? "");
	if (!credential) return badRequest("Missing Google credential.");

	const verification = await verifyGoogleIdToken(credential, env);
	if (!verification.ok) return unauthorized(verification.error || "Google verification failed.");

	return outputHTML({ provider, token: env.GITHUB_PAT });
};

const handleGitHubOAuthStart = async (request, env) => {
	const url = new URL(request.url);
	const provider = getProvider(url.toString());
	const csrfToken = String(url.searchParams.get("csrfToken") ?? "");

	if (!supportedProviders.includes(provider)) {
		return outputHTML({ provider, error: "Unsupported provider.", errorCode: "UNSUPPORTED_PROVIDER" });
	}
	if (!verifyCsrf(request, csrfToken)) {
		return outputHTML({ provider, error: "Session expired.", errorCode: "SESSION_EXPIRED" });
	}
	if (!env.GITHUB_OAUTH_CLIENT_ID || !env.GITHUB_OAUTH_CLIENT_SECRET) {
		return outputHTML({ provider, error: "GitHub OAuth is not configured.", errorCode: "MISCONFIGURED_GITHUB_OAUTH" });
	}

	const state = crypto.randomUUID().replaceAll("-", "");
	const redirectUri = env.GITHUB_OAUTH_REDIRECT_URI || `${url.origin}/auth/github/callback`;
	const authUrl = new URL("https://github.com/login/oauth/authorize");
	authUrl.searchParams.set("client_id", env.GITHUB_OAUTH_CLIENT_ID);
	authUrl.searchParams.set("redirect_uri", redirectUri);
	authUrl.searchParams.set("scope", "read:user user:email");
	authUrl.searchParams.set("state", state);
	authUrl.searchParams.set("allow_signup", "false");

	return new Response(null, {
		status: 302,
		headers: {
			Location: authUrl.toString(),
			"Cache-Control": "no-store",
			"Set-Cookie": `cms-auth-oauth-state=${state}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax; Secure`,
		},
	});
};

const handleGitHubOAuthCallback = async (request, env) => {
	const url = new URL(request.url);
	const provider = "github";
	const code = String(url.searchParams.get("code") ?? "");
	const state = String(url.searchParams.get("state") ?? "");
	const oauthError = String(url.searchParams.get("error") ?? "");
	const oauthErrorDesc = String(url.searchParams.get("error_description") ?? "");
	const cookies = parseCookie(request);
	const cookieState = String(cookies["cms-auth-oauth-state"] ?? "");

	if (oauthError) {
		return outputHTML({
			provider,
			error: oauthErrorDesc || "GitHub authorization was cancelled or rejected.",
			errorCode: "GITHUB_OAUTH_REJECTED",
		});
	}
	if (!code || !state || !cookieState || state !== cookieState) {
		return outputHTML({ provider, error: "GitHub OAuth state mismatch.", errorCode: "STATE_MISMATCH" });
	}
	if (!env.GITHUB_OAUTH_CLIENT_ID || !env.GITHUB_OAUTH_CLIENT_SECRET) {
		return outputHTML({ provider, error: "GitHub OAuth is not configured.", errorCode: "MISCONFIGURED_GITHUB_OAUTH" });
	}

	const redirectUri = env.GITHUB_OAUTH_REDIRECT_URI || `${url.origin}/auth/github/callback`;
	let tokenResp;
	try {
		tokenResp = await fetch("https://github.com/login/oauth/access_token", {
			method: "POST",
			headers: {
				Accept: "application/json",
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				client_id: env.GITHUB_OAUTH_CLIENT_ID,
				client_secret: env.GITHUB_OAUTH_CLIENT_SECRET,
				code,
				redirect_uri: redirectUri,
				state,
			}).toString(),
		});
	} catch {
		return outputHTML({ provider, error: "GitHub token exchange request failed.", errorCode: "TOKEN_EXCHANGE_REQUEST_FAILED" });
	}

	if (!tokenResp.ok) {
		return outputHTML({ provider, error: "Failed to exchange GitHub OAuth code.", errorCode: "TOKEN_EXCHANGE_FAILED" });
	}

	const tokenData = await tokenResp.json().catch(() => null);
	const accessToken = String(tokenData?.access_token ?? "");
	if (!accessToken) {
		return outputHTML({ provider, error: "GitHub did not return an access token.", errorCode: "MISSING_ACCESS_TOKEN" });
	}

	const ghHeaders = {
		Accept: "application/vnd.github+json",
		Authorization: `Bearer ${accessToken}`,
		"User-Agent": "google-sveltia-auth-worker",
	};

	let userResp;
	try {
		userResp = await fetch("https://api.github.com/user", { headers: ghHeaders });
	} catch {
		return outputHTML({ provider, error: "Failed to reach GitHub user API.", errorCode: "PROFILE_REQUEST_FAILED" });
	}
	if (!userResp.ok) {
		return outputHTML({ provider, error: "Failed to read GitHub user profile.", errorCode: "PROFILE_FETCH_FAILED" });
	}

	const user = await userResp.json().catch(() => ({}));
	const login = String(user?.login ?? "").toLowerCase();
	let email = String(user?.email ?? "").toLowerCase();

	if (!email) {
		let emailsResp;
		try {
			emailsResp = await fetch("https://api.github.com/user/emails", { headers: ghHeaders });
		} catch {
			emailsResp = null;
		}
		if (emailsResp?.ok) {
			const emails = await emailsResp.json().catch(() => []);
			const verified = Array.isArray(emails) ? emails.find((entry) => entry?.verified && entry?.email) : null;
			if (verified?.email) email = String(verified.email).toLowerCase();
		}
	}

	const hasAllowlist = toLowerList(env.ALLOWED_GITHUB_LOGINS).length || toLowerList(env.ALLOWED_GITHUB_EMAILS).length;
	if (!hasAllowlist) {
		return outputHTML({ provider, error: "GitHub allowlist is not configured.", errorCode: "MISSING_GITHUB_ALLOWLIST" });
	}

	const loginAllowed = login ? isAllowedGitHubLogin(login, env) : false;
	const emailAllowed = email ? isAllowedGitHubEmail(email, env) : false;
	if (!loginAllowed && !emailAllowed) {
		return outputHTML({ provider, error: "GitHub account is not in the allowlist.", errorCode: "GITHUB_NOT_ALLOWED" });
	}

	return outputHTML({ provider, token: env.GITHUB_PAT });
};

const text = (status, body) =>
	new Response(body, {
		status,
		headers: { "Content-Type": "text/plain;charset=UTF-8", "Cache-Control": "no-store" },
	});

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const { pathname } = url;

		if (request.method === "GET" && ["/auth", "/oauth/authorize"].includes(pathname)) {
			return handleAuth(request, env);
		}
		if (request.method === "POST" && pathname === "/auth/email") {
			return handleEmailAuth(request, env);
		}
		if (request.method === "POST" && pathname === "/auth/google") {
			return handleGoogleAuth(request, env);
		}
		if (request.method === "GET" && pathname === "/auth/github/start") {
			return handleGitHubOAuthStart(request, env);
		}
		if (request.method === "GET" && pathname === "/auth/github/callback") {
			return handleGitHubOAuthCallback(request, env);
		}
		if (request.method === "GET" && pathname === "/health") {
			return text(200, "ok");
		}
		return text(404, "Not Found");
	},
};
