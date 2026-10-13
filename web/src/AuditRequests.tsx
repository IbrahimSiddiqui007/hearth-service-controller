import {useEffect,useState} from 'react';
type Row={id:string;started_at:string;finished_at:string|null;method:string;route:string;status:string;http_status:number|null;service_id:string|null};
export function AuditRequests({request,serviceId}:{request:<T>(path:string)=>Promise<T>;serviceId?:string}){
  const [rows,setRows]=useState<Row[]>([]),[error,setError]=useState('');
  async function load(){try{setRows(await request<Row[]>(serviceId?'/services/'+serviceId+'/audit/requests':'/audit/requests'));setError('');}catch{setError('Write audit could not be loaded.');}}
  useEffect(()=>{void load();},[serviceId]);
  return <section className="panel"><div className="panel-heading"><h2>API write audit</h2><button className="button secondary" onClick={load}>Refresh write audit</button></div><p className="muted">Durable write intents and HTTP outcomes, including refused/null requests and interruptions. Accepted means the API returned a response; inspect the action history for the observed runtime outcome. Request bodies, query strings and credential values are omitted.</p>{error&&<p role="alert">{error}</p>}{rows.length?rows.map(row=><div className="credential-card" key={row.id}><strong>{row.method} {row.route} · {row.status}</strong><p>{new Date(row.started_at).toLocaleString()} · HTTP {row.http_status??'unknown'}{row.service_id?' · '+row.service_id:''}</p><small>Request {row.id}</small></div>):<p>No recorded write intents.</p>}</section>;
}
