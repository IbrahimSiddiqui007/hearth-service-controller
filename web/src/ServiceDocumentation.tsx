export type Documentation = { installation: string; backup_plan: string; recovery: string };
export const emptyDocumentation: Documentation = { installation: '', backup_plan: '', recovery: '' };
const sections = [['installation', 'Installation notes'], ['backup_plan', 'Backup plan'], ['recovery', 'Recovery runbook']] as const;

export function DocumentationEditor({ value, change }: { value: Documentation; change: (value: Documentation) => void }) {
  return <details><summary>Installation, backups & recovery</summary><p className="muted">Owner-maintained Markdown. Record the source, installation steps, backup location/schedule and restore checks. This documentation does not execute commands or verify that backups exist.</p>{sections.map(([key, title]) => <label className="field" key={key}>{title}<textarea rows={5} maxLength={15000} value={value[key]} onChange={e => change({ ...value, [key]: e.target.value })} /></label>)}</details>;
}

export function DocumentationOverview({ value }: { value: Documentation }) {
  return <section className="panel"><div className="panel-heading"><h2>Installation & recovery</h2><span className="read-only">Owner documentation</span></div>{sections.map(([key, title]) => <details key={key}><summary>{title}</summary><pre className="markdown-preview">{value[key] || 'No owner documentation recorded. Add it in Notes & setup.'}</pre></details>)}<p className="muted">Backup availability and restore success require separate verification.</p></section>;
}

export function DocumentationHistory({ rows }: { rows: { id: number; revision: number; ts: string; body: Partial<Documentation> }[] }) {
  if (!rows.length) return null;
  return <section className="panel"><h2>Previous setup & recovery notes</h2>{rows.map(row => <details key={row.id}><summary>{new Date(row.ts).toLocaleString()} · revision {row.revision}</summary>{sections.map(([key, title]) => <div key={key}><h3>{title}</h3><pre className="markdown-preview">{row.body[key] || 'No documentation at this revision.'}</pre></div>)}</details>)}</section>;
}
