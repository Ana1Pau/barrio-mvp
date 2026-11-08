function normalizeUrl(value) {
  return String(value || '').replace(/\/+$/, '');
}

export function createSupabaseDataClient({ url, secretKey, serviceRoleKey, fetchImpl = globalThis.fetch }) {
  const baseUrl = normalizeUrl(url);
  const serverKey = secretKey || serviceRoleKey;
  if (!baseUrl || !serverKey) throw new Error('Supabase server credentials are required');

  async function request(path, { method = 'GET', body, headers = {} } = {}) {
    const response = await fetchImpl(`${baseUrl}/rest/v1/${path}`, {
      method,
      headers: {
        apikey: serverKey,
        ...(!serverKey.startsWith('sb_secret_') ? { authorization: `Bearer ${serverKey}` } : {}),
        accept: 'application/json',
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      signal: AbortSignal.timeout(12000),
    });
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!response.ok) {
      const error = new Error(data?.message || `Supabase request failed (${response.status})`);
      error.status = response.status;
      error.code = data?.code;
      throw error;
    }
    return data;
  }

  const tablePath = (table, query = {}) => {
    const params = new URLSearchParams(query);
    return `${table}${params.size ? `?${params.toString()}` : ''}`;
  };

  return {
    select: (table, query) => request(tablePath(table, query)),
    insert: (table, body, prefer = 'return=representation') => request(table, { method: 'POST', body, headers: { prefer } }),
    update: (table, query, body) => request(tablePath(table, query), { method: 'PATCH', body, headers: { prefer: 'return=representation' } }),
    upsert: (table, body, onConflict) => request(tablePath(table, onConflict ? { on_conflict: onConflict } : {}), { method: 'POST', body, headers: { prefer: 'resolution=merge-duplicates,return=representation' } }),
    rpc: (functionName, args) => request(`rpc/${functionName}`, { method: 'POST', body: args }),
  };
}
