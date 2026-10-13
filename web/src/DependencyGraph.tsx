type Node = {id:string;name:string;status:string;dependencies:string[]};

export function DependencyGraph({service,entries}:{service:Node;entries:Node[]}) {
  const registry=new Map(entries.map(row=>[row.id,row]));
  function reachable(reverse:boolean){const result=new Set<string>(),queue=[service.id];while(queue.length){const current=queue.shift()!;const next=reverse?entries.filter(row=>row.dependencies.includes(current)).map(row=>row.id):(registry.get(current)?.dependencies||[]);for(const id of next){if(id!==service.id&&!result.has(id)){result.add(id);queue.push(id);}}}return [...result];}
  const prerequisites=reachable(false),dependents=reachable(true);
  const groups=[prerequisites.slice(0,12),[service.id],dependents.slice(0,12)];
  const rows=Math.max(1,...groups.map(group=>group.length)),height=rows*55+55;
  const positions=new Map<string,{x:number;y:number}>();groups.forEach((group,column)=>group.forEach((id,index)=>positions.set(id,{x:column*240+15,y:index*55+35})));
  return <section className="panel"><h2>Dependencies and stop impact</h2><p className="muted">Arrows point from a prerequisite to the service that needs it. Stopping {service.name} may affect {dependents.length} dependent {dependents.length===1?'service':'services'}, including indirect dependencies. This graph describes declared relationships; it does not stop anything or infer unrecorded dependencies.</p>
    <svg viewBox={'0 0 720 '+height} style={{width:'100%',height:'auto'}} role="img" aria-label={'Dependency graph for '+service.name}>
      <defs><marker id={'arrow-'+service.id} markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 Z" fill="currentColor"/></marker></defs>
      {['Prerequisites','Selected service','Potentially affected'].map((label,index)=><text key={label} x={index*240+15} y={18} fill="currentColor" fontSize={13}>{label}</text>)}
      {[...positions].flatMap(([id,to])=>(registry.get(id)?.dependencies||[]).filter(key=>positions.has(key)).map(key=>{const from=positions.get(key)!;return <path key={key+'-'+id} d={'M'+(from.x+190)+','+(from.y+17)+' C'+(from.x+215)+','+(from.y+17)+' '+(to.x-15)+','+(to.y+17)+' '+to.x+','+(to.y+17)} fill="none" stroke="currentColor" opacity={.4} markerEnd={'url(#arrow-'+service.id+')'}/>;}))}
      {[...positions].map(([id,point])=><a key={id} href={'#service/'+id} aria-label={registry.get(id)?.name||id}><rect x={point.x} y={point.y} width={190} height={35} rx={6} fill="var(--paper)" stroke="currentColor" opacity={id===service.id?1:.6}/><text x={point.x+8} y={point.y+22} fontSize={12} fill="currentColor">{(registry.get(id)?.name||id).slice(0,24)}</text><title>{registry.get(id)?.name||id} · {registry.get(id)?.status||'unknown'}</title></a>)}
    </svg>
    {(prerequisites.length>12||dependents.length>12)&&<p className="muted">Diagram shows at most twelve nodes per side; the lists include all declared relationships.</p>}
    <details><summary>All prerequisites ({prerequisites.length})</summary>{prerequisites.map(id=><p key={id}><a href={'#service/'+id}>{registry.get(id)?.name||id}</a> · {registry.get(id)?.status||'unknown'}</p>)}</details>
    <details open={dependents.length>0}><summary>Potential stop impact ({dependents.length})</summary>{dependents.length?dependents.map(id=><p key={id}><a href={'#service/'+id}>{registry.get(id)?.name||id}</a> · {registry.get(id)?.status||'unknown'}</p>):<p>No dependents are recorded.</p>}</details>
  </section>;
}
