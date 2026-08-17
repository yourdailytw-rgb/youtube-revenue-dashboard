/** Thin fetch wrapper. A 401 means the session lapsed — bounce to /login. */
async function request(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });

  if (res.status === 401) {
    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    throw new Error('Not authenticated');
  }
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (body?.error) message = body.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(message);
  }
  return res.json();
}

const qs = (params) => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') search.set(key, value);
  }
  const str = search.toString();
  return str ? `?${str}` : '';
};

export const api = {
  me: () => request('/api/me'),
  channels: () => request('/api/channels'),
  updateChannel: (id, patch) =>
    request(`/api/channels/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  disconnectChannel: (id, purge = false) =>
    request(`/api/channels/${id}${qs({ purge })}`, { method: 'DELETE' }),

  analytics: ({ start, end, channels, compare }) =>
    request(`/api/analytics${qs({ start, end, channels: channels?.join(','), compare })}`),

  videos: ({ start, end, channels, limit, sort, velocityHours }) =>
    request(
      `/api/videos${qs({ start, end, channels: channels?.join(','), limit, sort, velocityHours })}`
    ),

  estimates: (channel) => request(`/api/estimates${qs({ channel })}`),

  syncStatus: () => request('/api/sync/status'),
  liveStatus: () => request('/api/live-status'),
  livePoll: () => request('/api/live-poll', { method: 'POST' }),
  runSync: (full = false) => request(`/api/sync${qs({ full })}`, { method: 'POST' }),
  refreshTokens: () => request('/api/token-refresh', { method: 'POST' }),
  tokenHealth: () => request('/api/token-health'),
  storageStatus: () => request('/api/admin/storage-status'),

  exportUrl: ({ start, end, channels, scope = 'total' }) =>
    `/api/export${qs({ start, end, channels: channels?.join(','), scope })}`,
};
