# Lakewest AI

## Local development

Install the dependencies for the repository, backend, and frontend:

```sh
npm install
npm install --prefix server
npm install --prefix client
```

Configure provider credentials as server-side environment variables. The active backend loads `server/.env`; at least one of `GROQ_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `OPENROUTER_API_KEY` is required to start it. The agent provider chain specifically uses Groq and Anthropic. Keep credentials out of frontend `VITE_*` variables and do not commit real credentials. Local `.env` files are ignored by Git.

From the repository root, start the active backend:

```sh
npm run start:agent
```

In a separate terminal, start the Vite frontend:

```sh
npm --prefix client run dev
```

By default, the frontend runs at `http://localhost:5173`, the backend at `http://localhost:5000`, and the frontend API base is `http://localhost:5000`. Set `VITE_API_URL` in `client/.env.local` to the backend origin (for example, `http://localhost:5000`). Set server-side `CLIENT_URL` to the frontend origin (for example, `http://localhost:5173`) so the backend CORS policy allows it. These URL values are not secrets; provider credentials must stay server-side.

### Supabase authentication for investigations

Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` in `client/.env.local` for the frontend sign-in flow. Configure the corresponding server-side `SUPABASE_URL` and `SUPABASE_PUBLISHABLE_KEY` in `server/.env`; `server/.env.example` contains placeholders only. The backend uses the project Auth endpoint to verify the bearer access token on every `POST /api/agent` request. It does not trust client-supplied user IDs, roles, or capabilities. `/api/chat` and health checks remain public. Signing in does not grant tool capabilities. Restricted capabilities can be granted only by the server-side `AGENT_CAPABILITY_ALLOWLIST` JSON map in `server/.env` or deployment environment, keyed by the verified Supabase user ID; it is unset by default, so no capabilities are granted. Example: `{"<verified-supabase-user-id>":["web_search"]}`. Never source grants from frontend state, user metadata, email, or a user-controlled endpoint. Never use a Supabase service-role key for token verification or put credentials in committed files.

The backend health endpoint is `GET /api/health`. A successful health response confirms that the process and endpoint responded; it does not validate provider credentials, provider reachability, or successful live AI requests.

The existing root `start` and `dev` scripts are preserved. They still target the absent root `server.js`; use `start:agent` for the active development backend. The server package’s existing `start` script continues to launch the legacy `server/server.js` entry point.
