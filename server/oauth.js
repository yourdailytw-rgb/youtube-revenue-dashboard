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

function getRedirectUri() {
  if (config.RAILWAY_PUBLIC_DOMAIN) {
    return `https://${config.RAILWAY_PUBLIC_DOMAIN}/oauth2callback`;
  }
  return process.env.REDIRECT_URI || `http://localhost:${config.PORT}/oauth2callback`;
}

function makeOAuth2Client() {
  return new google.auth.OAuth2(config.CLIENT_ID, config.CLIENT_SECRET, getRedirectUri());
}

function generateAuthUrl() {
  return makeOAuth2Client().generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
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
