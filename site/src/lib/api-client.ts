const API_BASE = import.meta.env.PUBLIC_API_URL || 'https://api.quantmrkt.com';

interface RequestOptions {
  method?: string;
  body?: unknown;
  token?: string;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = 'GET', body, token } = options;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

export const api = {
  models: {
    list: (token?: string) => request('/v1/models', { token }),
    get: (namespace: string, token?: string) => request(`/v1/models/${namespace}`, { token }),
    verify: (namespace: string, token?: string) =>
      request(`/v1/models/${namespace}/verify`, { token }),
  },
  agents: {
    list: (token?: string) => request('/v1/agents', { token }),
    get: (id: string, token?: string) => request(`/v1/agents/${id}`, { token }),
    register: (data: unknown, token?: string) =>
      request('/v1/agents', { method: 'POST', body: data, token }),
  },
  migrate: {
    analyze: (data: unknown, token?: string) =>
      request('/v1/migrate/analyze', { method: 'POST', body: data, token }),
    report: (id: string, token?: string) => request(`/v1/migrate/report/${id}`, { token }),
  },
  hndl: {
    assess: (data: unknown, token?: string) =>
      request('/v1/hndl/assess', { method: 'POST', body: data, token }),
    database: (token?: string) => request('/v1/hndl/database', { token }),
  },
};
