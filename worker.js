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

	const entriesToMap = (entries) =>
		new Map(
			entries
				.map(([email, secret]) => [String(email).toLowerCase(), normalizeSecret(secret)])
				.filter(([email, parsed]) => email && parsed),
		);

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
	const googleButton =
		googleEnabled ?
			`
      <div class="google-wrap">
        <div id="googleSignInButton" class="google-button"></div>
      </div>
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
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 20px; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: radial-gradient(1200px 600px at 10% 0%, #eef2ff 0%, #f3f5fa 40%, #eef2f7 100%); color: #111827; }
    .wrap { width: min(460px, 100%); background: #fff; border-radius: 16px; padding: 28px; box-shadow: 0 16px 40px rgba(15, 23, 42, .10); border: 1px solid #e5e7eb; }
    h1 { margin: 0 0 8px; font-size: 22px; }
    p { margin: 0 0 18px; color: #374151; line-height: 1.5; }
    form { display: grid; gap: 10px; }
    label { font-weight: 600; font-size: 14px; }
    input { width: 100%; border: 1px solid #cbd5e1; border-radius: 10px; padding: 11px 12px; font-size: 14px; transition: border-color .15s ease, box-shadow .15s ease; background: #fff; }
    input:focus { outline: none; border-color: #4f46e5; box-shadow: 0 0 0 3px rgba(79, 70, 229, .16); }
    button { width: 100%; border: none; border-radius: 10px; background: linear-gradient(180deg, #1f2937 0%, #111827 100%); color: white; padding: 11px 14px; font-size: 14px; font-weight: 600; cursor: pointer; transition: transform .08s ease, box-shadow .15s ease; }
    button:hover { box-shadow: 0 8px 18px rgba(17, 24, 39, .18); }
    button:active { transform: translateY(1px); }
    .sep { margin: 18px 0 14px; display: flex; align-items: center; gap: 12px; color: #64748b; font-size: 12px; letter-spacing: .06em; font-weight: 600; }
    .sep::before, .sep::after { content: ""; height: 1px; flex: 1; background: #e2e8f0; }
    .google-wrap { width: 100%; min-height: 42px; }
    .google-button { width: 100%; min-height: 42px; }
    #status { margin-top: 14px; font-size: 14px; min-height: 20px; }
    .error { color: #b91c1c; }
    .ok { color: #047857; }
    .muted { color: #6b7280; font-size: 13px; }
    @media (max-width: 480px) {
      .wrap { padding: 20px; border-radius: 14px; }
      h1 { font-size: 20px; }
    }
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
	    const googleClientId = ${JSON.stringify(googleClientId)};
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
