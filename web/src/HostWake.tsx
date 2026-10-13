import {useEffect,useState} from 'react';
type Plan={host_name:string;mac:string;address:string;port:number;fingerprint:string;demo:boolean;notice:string};

export function HostWake({hostId,request}:{hostId:string;request:<T=any>(path:string,options?:RequestInit)=>Promise<T>}){
  const [plan,setPlan]=useState<Plan|null>(null),[confirmed,setConfirmed]=useState(false),[busy,setBusy]=useState(false),[detail,setDetail]=useState('');
  useEffect(()=>{let current=true;request<Plan>('/hosts/'+hostId+'/wake-plan').then(value=>{if(current)setPlan(value);}).catch(()=>{});return()=>{current=false;};},[hostId]);
  async function wake(){if(!plan)return;setBusy(true);setDetail('');try{const result=await request<{detail:string}>('/hosts/'+hostId+'/wake',{method:'POST',body:JSON.stringify({confirmed,fingerprint:plan.fingerprint})});setDetail(result.detail);setConfirmed(false);}catch(e){setDetail(String(e));request<Plan>('/hosts/'+hostId+'/wake-plan').then(setPlan).catch(()=>setPlan(null));setConfirmed(false);}finally{setBusy(false);}}
  if(!plan)return null;
  return <details><summary>{plan.demo?'Demo ':''}Wake host</summary><p className="muted">{plan.notice}</p><p>{plan.host_name} · {plan.mac} · {plan.address}:{plan.port}</p><label className="checkbox-label"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)} disabled={busy}/>I confirm this host and wake destination.</label><button className="button" disabled={busy||!confirmed} onClick={wake}>{busy?'Sending…':plan.demo?'Simulate wake packet':'Send wake packet'}</button>{detail&&<p role="status">{detail}</p>}</details>;
}
