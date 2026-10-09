export class APIError extends Error {
  constructor(message: string, public status: number) { super(message); }
}
export async function api<T>(path: string, data?: unknown): Promise<T> {
  const response = await fetch('/api' + path, {
    method: data === undefined ? 'GET' : 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
    headers: data === undefined ? {} : { 'Content-Type': 'application/json', 'X-Vault-Request': '1' },
    body: data === undefined ? undefined : JSON.stringify(data),
  });
  const body = await response.json().catch(() => ({ error: 'The server returned an unexpected response.' }));
  if (!response.ok) throw new APIError(body.error || 'Request failed', response.status);
  return body as T;
}
