import {useEffect, useState} from 'react';

type Plan = {host_name:string; fingerprint:string; actions:('suspend'|'shutdown')[]; affected:{id:string;name:string;status:string}[]; external_dependents:string[]; demo:boolean; notice:string};
type Status = {requests:{id:string; action:string; ts:string; status:string; active:number; detail:string}[]};

export function HostPower({hostId, request, refresh}: {hostId:string;request:<T>(path:string,options?:RequestInit)=>Promise<T>;refresh:()=>Promise<void>}) {
  const [plan,setPlan] = useState<Plan>();
  const [history,setHistory] = useState<Status>({requests:[]});
  const [action,setAction] = useState<'suspend'|'shutdown'>('suspend');
  const [confirmed,setConfirmed] = useState(false), [busy,setBusy] = useState(false), [detail,setDetail] = useState('');
  async function status() { try { setHistory(await request<Status>('/hosts/'+hostId+'/power-status')); } catch { setDetail('Power history could not be loaded.'); } }
  useEffect(()=>{void status();},[hostId]);
  async function review() {
    setBusy(true); setConfirmed(false); setPlan(undefined); setDetail('');
    try { const value = await request<Plan>('/hosts/'+hostId+'/power-plan'); setPlan(value); setAction(value.actions[0] || 'suspend'); if(!value.actions.length)setDetail('No supported power action is approved on this agent.'); }
    catch(e) {setDetail(e instanceof Error?e.message:String(e));}
    finally {setBusy(false);}
  }
  async function send() {
    if(!plan)return;
    setBusy(true); setDetail('');
    try {const result = await request<{detail:string}>('/hosts/'+hostId+'/power',{method:'POST',body:JSON.stringify({action,confirmed,fingerprint:plan.fingerprint})});setDetail(result.detail);}
    catch(e) {setDetail(e instanceof Error?e.message:String(e));}
    finally {setConfirmed(false);setPlan(undefined);await status();await refresh();setBusy(false);}
  }
  async function acknowledge(id:string) {
    setBusy(true);
    try {await request('/hosts/'+hostId+'/power/acknowledge',{method:'POST',body:JSON.stringify({operation_id:id,confirmed})});setDetail('Inspection acknowledged. The historical power outcome remains unverified.');await status();await refresh();}
    catch(e){setDetail(e instanceof Error?e.message:String(e));}
    finally{setConfirmed(false);setBusy(false);}
  }
  const pending = history.requests.find(row=>row.active);
  return <details><summary>Host suspend / shutdown</summary>
    <p className="muted">Review all registered services before requesting host power. Local controller and agent permissions are disabled by default. Nothing changes until you confirm and send a reviewed plan.</p>
    <button className="button secondary" disabled={busy || !!pending} onClick={review}>Review power plan</button>
    <button className="text-button" disabled={busy} onClick={status}>Refresh power history</button>
    {plan && <><p>{plan.host_name} · {plan.demo?'Synthetic demo':'Target permissions unverified'}</p><p className="warning-text">{plan.notice}</p>
      <h4>Registered services affected</h4>{plan.affected.map(row=><p key={row.id}>{row.name} · {row.status}</p>)}
      {plan.external_dependents.length>0 && <p className="warning-text">External declared dependents: {plan.external_dependents.join(', ')}</p>}
      <label className="field">Host power action<select value={action} disabled={busy || !plan.actions.length} onChange={e=>{setAction(e.target.value as 'suspend'|'shutdown');setConfirmed(false);}}>{plan.actions.map(value=><option key={value} value={value}>{value}</option>)}</select></label>
      <label className="checkbox-label"><input type="checkbox" checked={confirmed} disabled={busy} onChange={e=>setConfirmed(e.target.checked)} />I confirm this host, its affected services and the impact on all user sessions.</label>
      <button className="button" disabled={busy || !confirmed || !plan.actions.includes(action)} onClick={send}>{plan.demo?'Simulate':'Request'} {action}</button>
    </>}
    {pending && <><p className="warning-text">A previous {pending.action} request has an unverified outcome. Host writes stay blocked. A configured Wake-on-LAN request remains available for recovery.</p><p>{pending.detail}</p><label className="checkbox-label"><input type="checkbox" checked={confirmed} disabled={busy} onChange={e=>setConfirmed(e.target.checked)} />I inspected this host and its services and obtained fresh post-request observations.</label><button className="button secondary" disabled={busy || !confirmed} onClick={()=>acknowledge(pending.id)}>Acknowledge inspection</button></>}
    {detail && <p role="status">{detail}</p>}
    {history.requests.map(row=><p key={row.id}>{new Date(row.ts).toLocaleString()} · {row.action} · {row.status} · power state unverified</p>)}
  </details>;
}
