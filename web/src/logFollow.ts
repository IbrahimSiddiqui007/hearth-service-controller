/** Same-origin authenticated NDJSON follower. Abort on pause, navigation or unmount. */
export async function followLogs(serviceId: string, lines: number, signal: AbortSignal, append: (value: string) => void): Promise<void> {
  const token = sessionStorage.getItem('psc-token');
  const response = await fetch(`/api/v1/services/${encodeURIComponent(serviceId)}/logs/stream?lines=${lines}`, { signal, headers: token ? { Authorization: 'Bearer ' + token } : {} });
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event('psc-auth'));
    const error = await response.json().catch(() => ({}));
    throw new Error(typeof error.detail === 'string' ? error.detail : 'Log follower unavailable');
  }
  if (!response.body) throw new Error('Streaming is unavailable in this browser');
  const reader = response.body.getReader(), decoder = new TextDecoder();
  let pending = '';
  try {
    while (!signal.aborted) {
      const { done, value } = await reader.read();
      if (done) break;
      pending += decoder.decode(value, { stream: true });
      if (pending.length > 650000) throw new Error('Log frame exceeded size limit');
      let boundary: number;
      while ((boundary = pending.indexOf('\n')) >= 0) {
        const line = pending.slice(0, boundary); pending = pending.slice(boundary + 1);
        if (!line) continue;
        const row = JSON.parse(line);
        if (typeof row.content !== 'string' || row.content.length > 100001) throw new Error('Invalid log frame');
        if (row.kind === 'log') append(row.content);
        if (row.kind === 'error') throw new Error(row.content);
        if (row.kind === 'end') return;
      }
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}
