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
		{
			headers: {
				...htmlHeaders,
				"Set-Cookie": "cms-auth-csrf=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=Lax; Secure",
			},
		},
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

const parsePasswordUsers = (raw) => {
	if (!raw) return new Map();
	const text = raw.trim();

	if (!text) return new Map();

	try {
		if (text.startsWith("{")) {
			const parsed = JSON.parse(text);
			return new Map(Object.entries(parsed).map(([email, hash]) => [String(email).toLowerCase(), String(hash).toLowerCase()]));
		}

		if (text.startsWith("[")) {
			const parsed = JSON.parse(text);
			return new Map(parsed.filter((item) => item?.email && item?.passwordSha256).map((item) => [String(item.email).toLowerCase(), String(item.passwordSha256).toLowerCase()]));
		}
	} catch {
		return new Map();
	}

	return new Map(
		text
			.split(",")
			.map((entry) => entry.trim())
			.filter(Boolean)
			.map((pair) => {
				const [email, hash] = pair.split(":");
				return [String(email).toLowerCase(), String(hash ?? "").toLowerCase()];
			})
			.filter(([email, hash]) => email && hash),
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
	const googleButton =
		googleEnabled ?
			`
      <div id="g_id_onload"
        data-client_id="${escapeHtml(googleClientId)}"
        data-callback="onGoogleCredentialResponse"
        data-auto_prompt="false"></div>
      <div class="g_id_signin" data-type="standard" data-size="large"></div>
    `
		:	`<p class="muted">Google login is currently disabled.</p>`;

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
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: #f5f7fb; color: #111827; }
    .wrap { max-width: 420px; margin: 5vh auto; background: #fff; border-radius: 12px; padding: 24px; box-shadow: 0 10px 30px rgba(17,24,39,.08); }
    h1 { margin: 0 0 8px; font-size: 22px; }
    p { margin: 0 0 16px; color: #374151; }
    form { display: grid; gap: 12px; }
    label { font-weight: 600; font-size: 14px; }
    input { width: 100%; box-sizing: border-box; border: 1px solid #d1d5db; border-radius: 8px; padding: 10px 12px; font-size: 14px; }
    button { border: none; border-radius: 8px; background: #111827; color: white; padding: 10px 14px; font-size: 14px; cursor: pointer; }
    .sep { margin: 16px 0; text-align: center; color: #6b7280; font-size: 12px; }
    #status { margin-top: 12px; font-size: 14px; min-height: 20px; }
    .error { color: #b91c1c; }
    .ok { color: #047857; }
    .muted { color: #6b7280; font-size: 13px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Sign in to CMS</h1>
    <p>Use a whitelisted account. Backend provider: <strong>${escapeHtml(provider)}</strong>.</p>

    <form id="emailForm">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="username" required />
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
      <button type="submit">Sign in with Email</button>
    </form>

    <div class="sep">OR</div>
    ${googleButton}
    <div id="status" class="muted"></div>
  </div>

  <script>
    const csrfToken = ${JSON.stringify(csrfToken)};
    const provider = ${JSON.stringify(provider)};
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
	const expectedHash = users.get(email);
	if (!expectedHash) return unauthorized("Email is not allowlisted for password login.");

	const inputHash = await sha256Hex(password);
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
		if (request.method === "GET" && pathname === "/health") {
			return text(200, "ok");
		}
		return text(404, "Not Found");
	},
};
