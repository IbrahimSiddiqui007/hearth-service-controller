import React, { useState } from 'react';

type View = { ts?: string; stale: boolean; fingerprint: string; changes: { id: string; kind: string; name: string; source: string; change: string }[]; rows: unknown[]; warnings: string[]; gaps: string[] };
type Request = <T = any>(path: string, options?: RequestInit) => Promise<T>;

export function PersistenceInventory({ hostId, online, request }: { hostId: string; online: boolean; request: Request }) {
  const [value, setValue] = useState<View | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function run(action = '') {
    setBusy(true); setError('');
    try { setValue(await request<View>(`/hosts/${hostId}/persistence${action ? '/' + action : ''}`, action ? { method: 'POST', body: JSON.stringify(action === 'review' ? { fingerprint: value?.fingerprint } : {}) } : {})); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  return <details onToggle={e => { if (e.currentTarget.open && !value && !busy) run(); }}><summary>Persistence & listening ports</summary><p className="muted">Review cron/startup metadata and TCP listeners. Refresh requires local agent opt-in. Commands and secret values are omitted.</p><div className="heading-actions"><button className="button secondary small" disabled={busy || !online} onClick={() => run('refresh')}>{busy ? 'Reading…' : 'Refresh inventory'}</button>{value?.fingerprint && <button className="button secondary small" disabled={busy || value.stale || !value.changes.length} onClick={() => run('review')}>Acknowledge reviewed changes</button>}</div>{error && <p className="warning-text" role="alert">{error}</p>}{value && <><p className="muted">{value.rows.length} observed entries · {value.changes.length} unreviewed changes{value.stale ? ' · Stale inventory' : ''}</p>{value.changes.map(row => <div className="info-box" key={row.id}><span><strong>{row.change} · {row.kind} · {row.name}</strong><br />{row.source}</span></div>)}{[...value.warnings, ...value.gaps].map((message, index) => <p className="muted" key={index}>{message}</p>)}</>}</details>;
}
