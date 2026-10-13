import { useEffect, useState } from 'react';

type Policy = { enabled: boolean; timezone: string; acknowledge_components?:boolean; rules: { action: 'start' | 'stop'; cron: string }[] };
type Result = { policy: Policy; revision: number; next_windows: { ts: string; local_ts?:string; action: string }[]; runs: {minute: string; action: string; status: string; detail: string}[]; demo: boolean; limitations: string };
type LastControl = { action: string; source: string; ts: string; outcome: string; verified: boolean };

export function StopReason({ value, state }: { value?: LastControl; state: string }) {
  if (!value) return state === 'stopped' ? <div className="info-box">Stopped · reason unknown. No controller action is recorded for this state.</div> : null;
  return <div className="info-box">Last controller request: {value.action} · {value.source === 'schedule' ? 'scheduled window' : value.source === 'idle' ? 'verified inactivity' : 'manual action'} · {new Date(value.ts).toLocaleString()} · {value.outcome}{value.verified ? ' · resulting state observed at that time' : ' · resulting state unverified'}. Later external changes may have another cause.</div>;
}

export function ServiceSchedules({ sid, grouped, child=false, componentNames=[], request, notify, refresh, dirty }: { sid: string; grouped: boolean; child?:boolean; componentNames?:string[]; request: <T>(path:string, options?:RequestInit) => Promise<T>; notify:(message:string,error?:boolean)=>void; refresh:()=>Promise<void>; dirty:(value:boolean)=>void }) {
  const [result, setResult] = useState<Result>();
  const [policy, setPolicy] = useState<Policy>({enabled:false,timezone:'UTC',rules:[]});
  const [busy, setBusy] = useState(false), [error,setError] = useState('');
  const changed = !!result && JSON.stringify(policy) !== JSON.stringify(result.policy);
  useEffect(() => { dirty(changed); }, [changed]);
  useEffect(() => () => dirty(false), []);
  async function load() {
    setBusy(true);
    try { const data = await request<Result>('/services/' + sid + '/schedule'); setResult(data); setPolicy(data.policy); setError(''); }
    catch(e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  useEffect(() => { void load(); }, [sid]);
  async function save() {
    if (!result) return;
    setBusy(true); setError('');
    try { const data = await request<Result>('/services/' + sid + '/schedule', {method:'PUT',body:JSON.stringify({policy,revision:result.revision})}); setResult(data); setPolicy(data.policy); dirty(false); await refresh(); notify('Schedule saved. The current minute and missed windows will not run.'); }
    catch(e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  function update(index:number, value:Partial<Policy['rules'][number]>) { setPolicy(old => ({...old,rules:old.rules.map((row,i)=>i===index?{...row,...value}:row)})); }
  return <section className="panel">
    <div className="panel-heading"><h2>Service schedules</h2><button className="button secondary" disabled={busy || changed} onClick={load}>Reload schedule</button></div>
    <p className="muted">Each cron window is considered once in your chosen timezone. Fresh observations, control permission, free host reservations and safe dependencies are required. Skipped windows never run later.</p>
    {result?.demo && <p className="info-box">Demo only · rules can be saved and previewed; automatic dispatch is disabled.</p>}
    {child && <p className="warning-text">Schedule this component through its application parent.</p>}
    {grouped && !child && <label className="checkbox-label"><input type="checkbox" checked={policy.acknowledge_components || false} disabled={busy} onChange={e=>setPolicy(old=>({...old,acknowledge_components:e.target.checked}))} />I approve scheduled actions for this application and its linked components: {componentNames.join(', ')}.</label>}
    <label className="checkbox-label"><input type="checkbox" checked={policy.enabled} disabled={busy || child} onChange={e=>setPolicy(old=>({...old,enabled:e.target.checked}))} />Enable scheduled start and stop</label>
    <label className="field">Schedule timezone<input value={policy.timezone} maxLength={100} disabled={busy} onChange={e=>setPolicy(old=>({...old,timezone:e.target.value}))} placeholder="Asia/Dubai" /></label><p className="muted">Use an IANA name or UTC. Spring-forward nonexistent minutes are skipped. Fall-back repeated minutes run only at the first occurrence.</p>
    <p className="muted">Five fields: minute (0–59), hour (0–23), day (1–31), month (1–12), weekday (0–6, Sunday 0). Numbers, *, comma lists, ranges and /steps are supported. Restricted day and weekday fields use cron OR semantics.</p>
    {policy.rules.map((row,index)=><div className="credential-card" key={index}><div className="form-grid"><label className="field">Action {index+1}<select value={row.action} disabled={busy} onChange={e=>update(index,{action:e.target.value as 'start'|'stop'})}><option value="start">Start</option><option value="stop">Stop</option></select></label><label className="field">Local cron {index+1}<input maxLength={100} disabled={busy} value={row.cron} onChange={e=>update(index,{cron:e.target.value})} placeholder="0 23 * * *" /></label></div><button className="text-button" disabled={busy} onClick={()=>setPolicy(old=>({...old,rules:old.rules.filter((_,i)=>i!==index)}))}>Remove rule {index+1}</button></div>)}
    <div className="heading-actions"><button className="button secondary" disabled={busy || policy.rules.length>=8} onClick={()=>setPolicy(old=>({...old,rules:[...old.rules,{action:'stop',cron:'0 23 * * *'}]}))}>Add schedule rule</button><button className="button primary" disabled={busy || !result || !changed || (policy.enabled && !policy.rules.length)} onClick={save}>Save schedule</button><button className="text-button" disabled={busy || !changed} onClick={()=>{if(result)setPolicy(result.policy);}}>Discard schedule draft</button></div>
    {error && <p role="alert" className="warning-text">{error}</p>}
    <h3>Next saved windows · {result?.policy.timezone || 'UTC'}</h3><p className="muted">Preview of the next eight days; windows can still be skipped. The controller must remain running. Conflicting start/stop windows are refused.</p>
    {result?.next_windows.length ? result.next_windows.map((row,index)=><p key={index}>{row.local_ts || row.ts} · {row.action}</p>) : <p className="muted">No enabled windows in the preview range.</p>}
    <h3>Recent schedule decisions</h3>{result?.runs.length ? result.runs.map((row,index)=><div className="credential-card" key={index}><strong>{row.action} · {row.status}</strong><p>{row.minute} · {row.detail}</p></div>) : <p className="muted">No recorded schedule decisions.</p>}
  </section>;
}
