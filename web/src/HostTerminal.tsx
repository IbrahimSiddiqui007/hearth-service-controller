import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { InstallationReview } from './InstallationReview';

type Profile = { id: string; label: string; cwd: string; fingerprint: string };
type Entry = {ts: string; direction: string; content: string};
type Session = {id: string; name: string; started_at: string; ended_at: string | null; status: string; recording: boolean};
type Request = <T = any>(path: string, options?: RequestInit) => Promise<T>;

export function HostTerminal({ serviceId, request, download }: { serviceId: string; request: Request; download: (path:string,filename:string)=>Promise<void> }) {
  const [profiles, setProfiles] = useState<Profile[]>([]), [profile, setProfile] = useState(''), [demo, setDemo] = useState(false);
  const [confirmed, setConfirmed] = useState(false), [recording, setRecording] = useState(false), [busy, setBusy] = useState(false), [active, setActive] = useState(false), [error, setError] = useState('');
  const [sessions, setSessions] = useState<Session[]>([]), [entries, setEntries] = useState<Entry[] | null>(null);
  const [name, setName] = useState('Installation session');
  const [snapshots,setSnapshots]=useState(false);
  const mount = useRef<HTMLDivElement>(null), terminal = useRef<Terminal | null>(null), socket = useRef<WebSocket | null>(null), lease = useRef<string | null>(null);
  const alive = useRef(true);
  const observer = useRef<ResizeObserver | null>(null);
  const selected = profiles.find(item => item.id === profile);
  async function history() { setSessions(await request<Session[]>('/services/' + serviceId + '/terminal/sessions')); }
  useEffect(() => {
    let current = true;alive.current=true;
    request<{profiles: Profile[]; demo: boolean}>('/services/' + serviceId + '/terminal/profiles').then(result => { if (current) {setProfiles(result.profiles);setProfile(result.profiles[0]?.id || '');setDemo(result.demo);} }).catch(e => {if (current) setError(e.message);});
    history().catch(e=>{if(current)setError(e.message);});
    return () => { current = false;alive.current=false; observer.current?.disconnect(); observer.current=null; socket.current?.close(); socket.current = null; if (lease.current) request('/services/' + serviceId + '/terminal/sessions/' + lease.current + '/close', {method:'POST', body:'{}'}).catch(()=>{}); lease.current = null; terminal.current?.dispose(); terminal.current = null; };
  }, [serviceId]);

  async function open() {
    if (!selected || !confirmed || !mount.current) return;
    setBusy(true);setError('');setEntries(null);
    try {
      const opened = await request<{id: string; ticket: string}>('/services/' + serviceId + '/terminal/open', {method:'POST',body:JSON.stringify({profile:selected.id,fingerprint:selected.fingerprint,confirmed,recording,snapshots,name})});
      lease.current = opened.id;
      if(!alive.current||!mount.current){await request('/services/'+serviceId+'/terminal/sessions/'+opened.id+'/close',{method:'POST',body:'{}'});lease.current=null;return;}
      observer.current?.disconnect();terminal.current?.dispose();
      const term = new Terminal({cols:80, rows:24, scrollback:1000, fontSize:13, screenReaderMode:true, theme:{background:'#15231d',foreground:'#e4e9e5'}, linkHandler:{activate:()=>{},hover:()=>{},leave:()=>{}}, allowProposedApi:true});
      terminal.current = term;
      const fit = new FitAddon();term.loadAddon(fit);term.open(mount.current);
      const fitBounded = () => {const size=fit.proposeDimensions();if(size)term.resize(Math.max(20,Math.min(240,size.cols)),Math.max(5,Math.min(100,size.rows)));};
      fitBounded();term.textarea?.setAttribute('aria-label','Interactive terminal input');
      observer.current=new ResizeObserver(fitBounded);observer.current.observe(mount.current);
      // Output cannot write/query the clipboard or open terminal-supplied links.
      term.parser.registerOscHandler(52,()=>true);term.parser.registerOscHandler(8,()=>true);
      const url = new URL('/api/v1/services/' + serviceId + '/terminal/sessions/' + opened.id + '/ws', location.href);url.protocol=location.protocol==='https:'?'wss:':'ws:';
      const ws = new WebSocket(url);socket.current=ws;
      ws.onopen=()=>ws.send(JSON.stringify({ticket:opened.ticket}));
      ws.onmessage=event=> { try {const message=JSON.parse(event.data);if(message.kind==='ready'){setActive(true);setBusy(false);term.focus();ws.send(JSON.stringify({rows:term.rows,cols:term.cols}));}else if(message.kind==='output'){term.write(message.content);}else if(message.kind==='end'){term.writeln('\r\n'+message.detail);ws.close();}}catch{ws.close();setError('Invalid terminal response; session closed.');} };
      ws.onclose=()=>{if(alive.current){setActive(false);setBusy(false);history().catch(()=>{});}lease.current=null;};
      ws.onerror=()=>{setError('Terminal connection ended. Refresh profiles before retrying.');setBusy(false);};
      term.onData(data=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify({data}));});
      term.onResize(size=>{if(ws.readyState===WebSocket.OPEN)ws.send(JSON.stringify(size));});
    } catch(e) {setError(e instanceof Error?e.message:String(e));setBusy(false);if(lease.current){await request('/services/'+serviceId+'/terminal/sessions/'+lease.current+'/close',{method:'POST',body:'{}'}).catch(()=>{});lease.current=null;}}
  }
  function close() {if(socket.current?.readyState===WebSocket.OPEN)socket.current.send(JSON.stringify({kind:'close'}));else socket.current?.close();}
  return <section className="panel"><h2>Host terminal</h2><p className="muted">{demo?'Synthetic terminal; no command runs on any machine.':'Commands run with the ordinary agent account permissions. The working directory is not a filesystem sandbox.'} Sessions close after 15 minutes without input, one hour total, or disconnect.</p>
    {error && <p className="warning-text" role="alert">{error}</p>}
    <label className="field">Approved terminal profile<select value={profile} disabled={active||busy} onChange={e=>{setProfile(e.target.value);setConfirmed(false);}}>{profiles.map(item=><option value={item.id} key={item.id}>{item.label}</option>)}</select></label>{!profiles.length&&<p className="muted">No approved terminal profile is available. Configure a fixed shell profile locally on this agent.</p>}{selected&&<p>Working directory: <code>{selected.cwd}</code></p>}
    <label className="checkbox-label"><input type="checkbox" checked={confirmed} disabled={active||busy} onChange={e=>setConfirmed(e.target.checked)}/>I confirm the host, account permissions and working directory.</label>
    <label className="checkbox-label"><input type="checkbox" checked={recording} disabled={active||busy} onChange={e=>setRecording(e.target.checked)}/>Record this installation session with best-effort secret masking.</label><p className="muted">Recording is optional and bounded. Avoid typing credentials. A transcript alone does not prove a successful installation or a reproducible reinstall.</p>
    {recording&&<label className="field">Installation session name<input value={name} maxLength={100} disabled={active||busy} onChange={e=>setName(e.target.value)}/></label>}
    {recording&&<label className="checkbox-label"><input type="checkbox" checked={snapshots} disabled={active||busy} onChange={e=>setSnapshots(e.target.checked)}/>Capture before/after metadata and approved watched files. Requires local agent approval; unavailable providers remain evidence gaps.</label>}
    <div className="panel-heading"><button className="button primary" disabled={!confirmed||!selected||active||busy} onClick={open}>{busy?'Opening terminal…':'Open confirmed terminal'}</button><button className="text-button" disabled={!active&&!busy} onClick={close}>Close terminal</button></div>
    <div ref={mount} className="host-terminal" style={{minHeight:active?360:0,marginTop:16}} />
    <h3>Session history</h3>{sessions.map(item=><div className="inventory-rows" key={item.id}><span>{item.name} · {new Date(item.started_at).toLocaleString()} · {item.status} · {item.status==='reconstructed'?'history import':item.recording?'recorded':'content not recorded'}<br/><code>{item.id}</code></span>{!!item.recording&&item.status!=='reconstructed'&&<><button className="text-button" onClick={()=>request<{entries:Entry[]}>('/services/'+serviceId+'/terminal/sessions/'+item.id).then(result=>setEntries(result.entries)).catch(e=>setError(e.message))}>Review masked recording</button><button className="text-button" onClick={()=>download('/services/'+serviceId+'/terminal/sessions/'+item.id+'/cast',serviceId+'-installation.cast').catch(e=>setError(e.message))}>Export masked cast</button></>}</div>)}{entries&&<pre className="file-content">{entries.map(entry=>`[${entry.direction}] ${entry.content}`).join('')}</pre>}
    <InstallationReview serviceId={serviceId} request={request} download={download} refresh={history} sessions={sessions}/>
  </section>;
}
