# Deploying v2

Everything is committed and ready. The commit fast-forwards `main` (no force
push, v1 history preserved), so Railway will auto-deploy it.

---

## Step 0 — BEFORE anyone connects a channel (do this first)

This is the step that decides whether the connections last. In Google Cloud
Console, project `youtube-revenue-tracker-491907`:

1. **APIs & Services → OAuth consent screen → Publishing status = "In production".**

   If it says *Testing*, click **Publish app**. Two things break otherwise:
   - refresh tokens die after 7 days (this is exactly why all 5 current
     connections are dead — their tokens carried a 7-day expiry)
   - only accounts listed as *test users* can authorise at all, so your
     colleague would be blocked

2. **Credentials → OAuth 2.0 Client ID → Authorised redirect URIs** must contain:
   ```
   https://youtube-revenue-dashboard-production.up.railway.app/oauth2callback
   ```
   (already there for v1 — just confirm it survived)

You can tell it worked: tokens minted in production mode do **not** carry a
`refresh_token_expires_in` field. The Settings tab will show every channel as
*healthy* and stay that way past a week.

---

## Step 1 — Push

Authenticate once (this is the only thing that needs your hands):

```bash
gh auth login          # GitHub.com → HTTPS → login with a browser
```

Then, from the project directory:

```bash
git push origin d2ea940:refs/tags/v1-final   # rollback point (optional but cheap)
git push origin deploy-v2:main               # triggers the Railway deploy
```

Railway picks up the push, runs `npm run build` (installs and builds the React
client) and starts with `npm start`.

**Rollback if anything goes wrong:** `git push -f origin v1-final:main`

---

## Step 2 — Railway variables

Existing v1 variables all still apply and need no changes:
`CLIENT_ID`, `CLIENT_SECRET`, `DASHBOARD_PASSWORD`, `RAILWAY_API_TOKEN`,
`RAILWAY_SERVICE_ID`, `RAILWAY_ENVIRONMENT_ID`, `STORED_TOKENS`.

**Add one:**

| Variable | Value | Why |
|---|---|---|
| `NIXPACKS_NODE_VERSION` | `24` | v2 uses built-in `node:sqlite`, which needs Node 24+. `engines` in package.json should cover it, but this removes all doubt. |

**Optional — per-user logins** (you said you and 2 colleagues need access):

| Variable | Value |
|---|---|
| `DASHBOARD_USERS` | `fatlum:pick-a-password,colleague1:pick-another,colleague2:pick-another` |

Leave `DASHBOARD_PASSWORD` in place as a fallback; both work simultaneously.

**Confirm the Volume is still mounted at `/data`.** Both `tokens.json` and the
new `metrics.db` live there. Without it, every deploy wipes tokens *and* all
cached history. The Settings tab shows a red banner if it is missing.

---

## Step 3 — Your colleague connects the channels

Send them:

1. **https://youtube-revenue-dashboard-production.up.railway.app**
2. The dashboard password
3. Then: click **Connect channel** → sign in with the Google account that owns
   the channel → authorise. Repeat for each of the 5 channels.

Each connection immediately starts a full backfill from `2024-01-01`. That is a
few minutes of API calls per channel — the dashboard fills in as it lands, and
**Settings → Data sync** shows progress.

They need no access to Railway, GitHub or Google Cloud — only the dashboard
password.

---

## Step 4 — Verify

In the dashboard:

- **Settings** — all 5 channels *healthy*, volume banner green, day count climbing
- **Overview** — the last 2 days appear in purple with a dashed line
- **Estimator** — per-channel back-tested accuracy against real reported revenue

That accuracy number is the one that matters. It needs ~2 weeks of history per
channel before it means anything; below 10 training days the model falls back to
a plain average RPM and reports low confidence.

Locally you can get the same figures with:

```bash
npm run backtest
```
