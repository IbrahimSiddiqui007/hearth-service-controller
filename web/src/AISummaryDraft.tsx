import {useState} from 'react';

export function AISummaryDraft({serviceId,request,applyDraft}:{serviceId:string;request:<T=any>(path:string,options?:RequestInit)=>Promise<T>;applyDraft:(text:string)=>void}) {
  const [draft,setDraft]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState('');
  async function generate(){setBusy(true);setError('');try{const value=await request<{draft:string}>('/services/'+serviceId+'/summary-draft',{method:'POST',body:'{}'});setDraft(value.draft);}catch(e){setError(String(e));}finally{setBusy(false);}}
  return <details><summary>Draft a description with Local AI</summary><p className="muted">Uses stored observed metadata and up to two verified configuration-history files. Advice only; purpose and deployment remain unverified. The existing description changes only when you use the draft and save this notebook.</p>{error&&<p className="warning-text" role="alert">{error}</p>}<button className="button" disabled={busy} onClick={generate}>{busy?'Drafting…':'Generate editable description'}</button>{draft&&<><label className="field">Unverified description draft<textarea rows={4} maxLength={2000} value={draft} onChange={e=>setDraft(e.target.value)}/></label><button className="text-button" onClick={()=>applyDraft(draft)}>Use in description field</button></>}</details>;
}
