import React,{useState} from 'react';
export function VaultVerification({sid,revision,credentials,api}:{sid:string;revision:number;credentials:{label:string;vault_ref:string}[];api:<T>(path:string,init?:RequestInit)=>Promise<T>}) {
 const [results,setResults]=useState<Record<number,string>>({}),[busy,setBusy]=useState<number|null>(null);
 async function check(index:number){setBusy(index);try{const r=await api<{status:string;notice:string}>('/services/'+sid+'/credentials/verify',{method:'POST',body:JSON.stringify({index,revision})});setResults(v=>({...v,[index]:r.status+' · '+r.notice}));}catch(e){setResults(v=>({...v,[index]:String(e)}));}finally{setBusy(null);}}
 return <section className="panel core-panel"><h2>Check linked vault items</h2><p>Uses an already unlocked, locally approved Bitwarden session. No vault login, sync or credential export occurs.</p>{credentials.length?credentials.map((c,i)=><div className="info-box" key={i}><strong>{c.label}</strong><button className="button secondary" disabled={busy!==null} onClick={()=>check(i)}>Check item {i+1}</button>{results[i]&&<p role="status">{results[i]}</p>}</div>):<p>No credential pointers saved.</p>}</section>;
}
