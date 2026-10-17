from urllib.parse import urlencode
from datetime import datetime,timezone
from fastapi import HTTPException
from controller.schedules import fresh


def register(app,demo,require,agent_request):
    def host(hid):
        row=require('hosts',hid)
        if not demo and (row.get('status')!='online' or not row.get('signing_env') or not row.get('physical_host_id') or not fresh(row.get('last_seen'),datetime.now(timezone.utc))):raise HTTPException(409,'Host browsing needs fresh online identity and signed transport')
        return row

    @app.get('/api/v1/hosts/{hid}/browse-roots')
    async def roots(hid:str):
        row=host(hid)
        result={'profiles':['example'],'physical_host_id':row.get('physical_host_id'),'os':row.get('active_os')} if demo else await agent_request(row,'GET','/host-files/profiles')
        if not isinstance(result,dict) or not isinstance(result.get('profiles'),list) or len(result['profiles'])>8:raise HTTPException(502,'Invalid host browse approval response')
        if not demo and (result.get('physical_host_id')!=row['physical_host_id'] or result.get('os')!=row.get('active_os')):raise HTTPException(409,'Host identity changed')
        return {'profiles':result['profiles'],'demo':demo}

    @app.get('/api/v1/hosts/{hid}/browse')
    async def browse(hid:str,profile:str,path:str='',confirmed:bool=False):
        if not confirmed:raise HTTPException(409,'Explicitly open the separately approved host browser')
        row=host(hid)
        selected=await roots(hid)
        if profile not in selected['profiles']:raise HTTPException(403,'Choose an approved host root')
        if demo:
            if not path:return {'kind':'directory','path':'','entries':[{'name':'README.md','directory':False,'size':64}],'readonly':True}
            if path!='README.md':raise HTTPException(404,'Demo host file not found')
            return {'kind':'file','path':path,'content':'# Synthetic host browser\nRead-only, separately approved scope.','readonly':True}
        return await agent_request(row,'GET','/host-files?'+urlencode({'profile':profile,'path':path}))
