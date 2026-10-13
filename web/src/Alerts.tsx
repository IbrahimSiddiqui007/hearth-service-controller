import React, { useEffect, useState } from 'react';
import { Bell, Check, Loader2, RefreshCw, Send } from 'lucide-react';

type Request = <T = any>(path: string, options?: RequestInit) => Promise<T>;
type Profile = { enabled: boolean; channel: 'ntfy' | 'telegram'; endpoint: string; topic: string; token_env: string; chat_id: string; restart_threshold: number; restart_window_s: number };
type Delivery = { id: number; ts: string; message: string; status: string; attempts: number; detail: string };
type Status = Profile & { configured: boolean; reason: string; demo: boolean; deliveries: Delivery[] };
const errorText = (e: unknown) => e instanceof Error ? e.message : String(e);

export function Alerts({ request }: { request: Request }) {
  const [profile, setProfile] = useState<Profile | null>(null), [status, setStatus] = useState<Status | null>(null);
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState(false);
  function accept(value: Status, reset = true) {
    setStatus(value);
    if (reset) { const { enabled, channel, endpoint, topic, token_env, chat_id, restart_threshold, restart_window_s } = value; setProfile({ enabled, channel, endpoint, topic, token_env, chat_id, restart_threshold, restart_window_s }); }
  }
  useEffect(() => { request<Status>('/notifications').then(value => accept(value)).catch(e => { setMessage(errorText(e)); setError(true); }); }, []);
  async function save(test = false) {
    if (!profile) return;
    setBusy(true); setError(false); setMessage('');
    try {
      const saved = await request<Status>('/notifications', { method: 'PUT', body: JSON.stringify(profile) });
      accept(saved);
      if (test) {
        const result = await request<{ outcomes: { status: string; detail: string }[] }>('/notifications/test', { method: 'POST', body: '{}' });
        accept(await request<Status>('/notifications'), false);
        setMessage(result.outcomes.map(row => row.detail).join(' · ') || 'Test queued; refresh delivery status.');
        setError(result.outcomes.some(row => !['delivered', 'simulated'].includes(row.status)));
      } else setMessage('Alert settings saved.');
    } catch (e) { setError(true); setMessage(errorText(e)); } finally { setBusy(false); }
  }
  async function refresh() { setBusy(true); try { accept(await request<Status>('/notifications'), false); setError(false); setMessage('Delivery status refreshed.'); } catch (e) { setError(true); setMessage(errorText(e)); } finally { setBusy(false); } }
  return <section className="panel alerts-panel"><div className="panel-heading"><h2>Alerts & notifications</h2><Bell size={18} /></div>
    {status?.demo && <p className="info-box">Demo deliveries are simulated. No notification server is contacted.</p>}
    {profile ? <form onSubmit={e => { e.preventDefault(); save(); }}><fieldset disabled={busy} className="alert-fields">
      <label className="checkbox-label enable-check"><input type="checkbox" checked={profile.enabled} onChange={e => setProfile({ ...profile, enabled: e.target.checked })} />Enable external alerts</label>
      <div className="form-grid"><label className="field">Alert channel<select value={profile.channel} onChange={e => setProfile({ ...profile, channel: e.target.value as Profile['channel'] })}><option value="ntfy">ntfy</option><option value="telegram">Telegram</option></select></label>
        <label className="field">Notification token environment variable<input value={profile.token_env} placeholder="PSC_NOTIFY_LAB" pattern="(PSC_NOTIFY_[A-Z0-9_]+)?" onChange={e => setProfile({ ...profile, token_env: e.target.value })} /><small>Enter the variable name only. Its value is configured on the controller.</small></label></div>
      {profile.channel === 'ntfy' ? <div className="form-grid"><label className="field">ntfy origin<input type="url" required={profile.enabled} placeholder="https://ntfy.example" value={profile.endpoint} onChange={e => setProfile({ ...profile, endpoint: e.target.value })} /></label><label className="field">ntfy topic<input required={profile.enabled} pattern="[a-zA-Z0-9_-]+" value={profile.topic} onChange={e => setProfile({ ...profile, topic: e.target.value })} /></label></div> : <label className="field">Telegram chat ID<input required={profile.enabled} value={profile.chat_id} placeholder="-123456789 or @channel" onChange={e => setProfile({ ...profile, chat_id: e.target.value })} /><small>Telegram also requires a PSC_NOTIFY_* environment variable containing the bot token.</small></label>}
      <div className="form-grid"><label className="field">Repeated restart count<input type="number" min={2} max={20} required value={profile.restart_threshold} onChange={e => setProfile({ ...profile, restart_threshold: Number(e.target.value) })} /></label><label className="field">Restart window (seconds)<input type="number" min={60} max={3600} required value={profile.restart_window_s} onChange={e => setProfile({ ...profile, restart_window_s: Number(e.target.value) })} /></label></div>
      <p className="muted">Alerts cover health failures/recoveries, offline hosts, repeated restarts and sustained host thresholds. Changed preferences cancel pending deliveries; identical saves preserve them.</p>
      <div className="heading-actions"><button className="button primary" type="submit">{busy ? <Loader2 className="spin" size={15} /> : <Check size={15} />}Save alerts</button><button className="button secondary" type="submit" disabled={!profile.enabled} onClick={e => { if (e.currentTarget.form?.reportValidity()) { e.preventDefault(); save(true); } }}><Send size={15} />{status?.demo ? 'Save & simulate test' : 'Save & send test'}</button></div>
    </fieldset></form> : !message && <Loader2 className="spin" size={18} />}
    {status && <p className="muted">{status.configured ? 'Saved channel is configured.' : status.reason}</p>}
    {message && <p className={error ? 'warning-text' : 'muted'} role="status">{message}</p>}
    <div className="panel-heading"><h3>Recent deliveries</h3><button className="text-button" disabled={busy} onClick={refresh}><RefreshCw size={14} />Refresh deliveries</button></div>
    <div className="delivery-list">{status?.deliveries.length ? status.deliveries.map(row => <div key={row.id}><strong>{row.status} · {row.attempts} attempts</strong><small>{new Date(row.ts).toLocaleString()}</small><p>{row.message}</p><small>{row.detail || 'Awaiting delivery'}</small></div>) : <p className="muted">No deliveries yet. Alerts start disabled.</p>}</div>
  </section>;
}

export type TelemetryPolicy = { enabled: boolean; cpu_percent: number; memory_percent: number; disk_percent: number; temperature_c: number; sustained_samples: number };
type ThresholdHost = { id: string; name: string; telemetry_policy?: TelemetryPolicy; telemetry_alerts?: Record<string, boolean>; telemetry_streaks?: Record<string, number> };
const defaults: TelemetryPolicy = { enabled: false, cpu_percent: 90, memory_percent: 90, disk_percent: 90, temperature_c: 80, sustained_samples: 3 };
export function HostThresholds({ host, request, saved }: { host: ThresholdHost; request: Request; saved: () => Promise<unknown> }) {
  const [policy, setPolicy] = useState<TelemetryPolicy>({ ...defaults, ...host.telemetry_policy });
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(''), [error, setError] = useState(false);
  useEffect(() => { setPolicy({ ...defaults, ...host.telemetry_policy }); }, [JSON.stringify(host.telemetry_policy)]);
  async function save(e: React.FormEvent) { e.preventDefault(); setBusy(true); try { await request('/hosts/' + host.id + '/telemetry-policy', { method: 'PUT', body: JSON.stringify(policy) }); await saved(); setError(false); setMessage('Threshold policy saved; observation streaks reset.'); } catch (e) { setError(true); setMessage(errorText(e)); } finally { setBusy(false); } }
  const active = Object.entries(host.telemetry_alerts || {}).filter(([, value]) => value).map(([key]) => key.replace('_percent', '').replace('_c', ''));
  return <details className="host-thresholds"><summary>Host alert thresholds · {active.length ? active.join(', ') + ' high' : 'no active alerts'}</summary><form onSubmit={save}><fieldset disabled={busy} className="alert-fields">
    <label className="checkbox-label"><input type="checkbox" checked={policy.enabled} onChange={e => setPolicy({ ...policy, enabled: e.target.checked })} />Enable thresholds for {host.name}</label>
    <div className="form-grid">{([['cpu_percent', 'CPU threshold (%)', 100], ['memory_percent', 'Memory threshold (%)', 100], ['disk_percent', 'Disk threshold (%)', 100], ['temperature_c', 'Temperature threshold (°C)', 150], ['sustained_samples', 'Consecutive high samples', 10]] as const).map(([key, label, max]) => <label className="field" key={key}>{label}<input type="number" min={1} max={max} step={key === 'sustained_samples' ? 1 : 'any'} required value={policy[key]} onChange={e => setPolicy({ ...policy, [key]: Number(e.target.value) })} /></label>)}</div>
    <p className="muted">Disk uses the highest known volume usage. Unknown readings break a pending streak and preserve active alerts until a known recovery. External delivery also requires enabled notification settings.</p><button className="button secondary small" type="submit">{busy ? <Loader2 className="spin" size={14} /> : <Check size={14} />}Save host thresholds</button>
  </fieldset></form>{message && <p role="status" className={error ? 'warning-text' : 'muted'}>{message}</p>}</details>;
}
