/**
 * Google OAuth client factory + proactive token refresh.
 *
 * Critical details carried over from v1 (do not change without reading the
 * handoff notes):
 *   - access_type: 'offline'  -> required to receive a refresh_token
 *   - prompt: 'consent'       -> guarantees a fresh refresh_token every time
 *   - The consent screen must stay in Production mode; Testing mode revokes
 *     refresh tokens after 7 days.
 */

const { google } = require('googleapis');
const config = require('./config');
const { loadTokens, saveTokens, channelHealth } = require('./tokens');

/**
 * Where Google sends the user back after consent.
 *
 * Resolution order matters. The whole flow breaks if the callback URL does not
 * point at the host the user is actually browsing — send someone on another
 * machine to http://localhost:3000/oauth2callback and their browser refuses the
 * connection, because that is *their* localhost, not the server's.
 *
 *   1. REDIRECT_URI            explicit override, always wins
 *   2. RAILWAY_PUBLIC_DOMAIN   set by Railway in production
 *   3. the request's own host  covers tunnels, proxies and any other domain
 *   4. localhost               local development fallback
 *
 * Whichever is used must also be registered in the Google Cloud Console under
 * the OAuth client's Authorised redirect URIs, or Google returns
 * redirect_uri_mismatch.
 */
function getRedirectUri(req) {
  if (process.env.REDIRECT_URI) return process.env.REDIRECT_URI;

  if (config.RAILWAY_PUBLIC_DOMAIN) {
    return `https://${config.RAILWAY_PUBLIC_DOMAIN}/oauth2callback`;
  }

  if (req) {
    // Behind a tunnel or proxy these headers carry the URL the user typed.
    const forwardedHost = req.headers['x-forwarded-host'];
    const host = forwardedHost || req.headers.host;
    if (host && !host.startsWith('localhost') && !host.startsWith('127.0.0.1')) {
      const proto = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
      return `${proto}://${host}/oauth2callback`;
    }
    if (host) return `http://${host}/oauth2callback`;
  }

  return `http://localhost:${config.PORT}/oauth2callback`;
}

function makeOAuth2Client(req) {
  return new google.auth.OAuth2(config.CLIENT_ID, config.CLIENT_SECRET, getRedirectUri(req));
}

function generateAuthUrl(req) {
  return makeOAuth2Client(req).generateAuthUrl({
    access_type: 'offline',
    // 'consent' guarantees a fresh refresh_token every time.
    // 'select_account' forces the account chooser — without it Google silently
    // reuses whichever account the browser is already signed into, which is
    // wrong here: each channel lives on a different account, so connecting five
    // channels means picking a different account five times.
    prompt: 'consent select_account',
    scope: config.SCOPES,
  });
}

/**
 * An OAuth client for one channel that persists any silently-refreshed tokens.
 */
function clientForChannel(channelId, tokenData) {
  const client = makeOAuth2Client();
  client.setCredentials(tokenData.tokens);
  client.on('tokens', (newTokens) => {
    const all = loadTokens();
    if (all[channelId]) {
      all[channelId].tokens = { ...all[channelId].tokens, ...newTokens };
      saveTokens(all);
    }
  });
  return client;
}

function isExpiredError(message = '') {
  return (
    message.includes('invalid_grant') ||
    message.includes('Token has been expired') ||
    message.includes('Token has been revoked') ||
    message.includes('expired') ||
    message.includes('revoked')
  );
}

/** Refresh every channel's access token. Runs at startup and on an interval. */
async function refreshAllTokens() {
  const allTokens = loadTokens();
  const ids = Object.keys(allTokens);
  if (ids.length === 0) {
    console.log('[refresh] No channels to refresh');
    return { refreshed: 0, failed: 0, total: 0 };
  }

  let refreshed = 0;
  let failed = 0;

  for (const [channelId, data] of Object.entries(allTokens)) {
    // Channels created by `npm run seed` have no real Google credentials.
    if (data.mock) {
      channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString(), mock: true };
      continue;
    }
    if (!data.tokens || !data.tokens.refresh_token) {
      console.warn(`[refresh] ${data.channelTitle}: no refresh_token, skipping`);
      channelHealth[channelId] = {
        status: 'expired',
        error: 'No refresh token',
        lastChecked: new Date().toISOString(),
      };
      failed++;
      continue;
    }

    const client = makeOAuth2Client();
    client.setCredentials(data.tokens);
    try {
      const { credentials } = await client.refreshAccessToken();
      allTokens[channelId].tokens = { ...data.tokens, ...credentials };
      channelHealth[channelId] = { status: 'ok', error: null, lastChecked: new Date().toISOString() };
      refreshed++;
    } catch (err) {
      channelHealth[channelId] = {
        status: isExpiredError(err.message) ? 'expired' : 'error',
        error: err.message,
        lastChecked: new Date().toISOString(),
      };
      console.error(`[refresh] ${data.channelTitle}: FAILED — ${err.message}`);
      failed++;
    }
  }

  if (refreshed > 0) saveTokens(allTokens);
  console.log(`[refresh] Done: ${refreshed} refreshed, ${failed} failed out of ${ids.length} channels`);
  return { refreshed, failed, total: ids.length };
}

module.exports = {
  getRedirectUri,
  makeOAuth2Client,
  generateAuthUrl,
  clientForChannel,
  refreshAllTokens,
  isExpiredError,
};
