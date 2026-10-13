import { useEffect, useState } from 'react';

type Finding = { id: string; source: string; category: string; last_seen: string; revision: number; vault_ref: string };

export function SecretFindings({ sid, api, notify }: { sid: string; api: <T>(path: string, options?: RequestInit) => Promise<T>; notify: (message: string, error?: boolean) => void }) {
  const [rows, setRows] = useState<Finding[]>([]);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [scope, setScope] = useState('unavailable');
  async function load() {
    setBusy(true);
    try { const result = await api<{ findings: Finding[]; file_scan_scope: string }>('/services/' + sid + '/secret-findings'); setRows(result.findings); setScope(result.file_scan_scope); setDrafts({}); setError(''); }
    catch { setError('Findings could not be loaded. Retry to review them.'); }
    finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, [sid]);
  async function save(row: Finding) {
    setBusy(true);
    try {
      const result = await api<{ findings: Finding[] }>('/services/' + sid + '/secret-findings/' + row.id, { method: 'PUT', body: JSON.stringify({ revision: row.revision, pointer: { label: 'Owner-linked finding', vault_ref: drafts[row.id] ?? row.vault_ref } }) });
      setRows(result.findings); notify('Reference saved. Vault existence and secret removal remain unverified.');
    } catch { notify('Reference was refused or the finding changed. Check the reference and reload.', true); }
    finally { setBusy(false); }
  }
  return <section className="panel">
    <div className="panel-heading"><h2>Possible embedded credentials</h2><button className="button secondary" disabled={busy} onClick={load}>Reload findings</button></div>
    <p className="muted">Checks cover discovery metadata, locally approved exact files and rejected configuration drafts. File-scan scope: {scope}. Secret-bearing filenames are flagged without reading their contents. No file crawl or vault login occurs. Findings store no values, excerpts or value hashes. Detection is best-effort.</p>
    {error ? <p role="alert">{error}</p> : !rows.length && <p>{busy ? 'Loading findings…' : 'No recorded findings. This does not prove that credentials are absent.'}</p>}
    {rows.map(row => <div className="credential-card" key={row.id}>
      <strong>{row.category}</strong><p>{row.source} · Last observed {new Date(row.last_seen).toLocaleString()}</p>
      <p className="muted">{row.vault_ref ? 'Owner linked · vault item unverified · removal unverified' : 'No owner vault link · may already be vaulted elsewhere'}</p>
      <label className="field">Vault item link or ID<input maxLength={1000} value={drafts[row.id] ?? row.vault_ref} onChange={e => setDrafts(old => ({ ...old, [row.id]: e.target.value }))} /></label>
      <button className="button secondary" disabled={busy} onClick={() => save(row)}>Save finding link</button>
    </div>)}
    <p className="muted">Linking records your reference only. Move or rotate credentials separately; a link never marks a secret removed or a file safe to edit.</p>
  </section>;
}
