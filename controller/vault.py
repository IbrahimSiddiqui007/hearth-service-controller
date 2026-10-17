import re
from urllib.parse import urlsplit
from fastapi import HTTPException
from controller.store import now
from shared.models import StrictModel
from pydantic import Field


class VaultReview(StrictModel):
    index: int = Field(ge=0,le=49)
    revision: int = Field(ge=1)


def item_id(reference):
    # Standard item IDs and Bitwarden web-vault /vault?...itemId= UUID links.
    pattern = r'[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}'
    if re.fullmatch(pattern, reference):
        return reference
    parsed = urlsplit(reference)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(422,'Select an exact UUID item reference or an HTTPS vault link')
    candidates = re.findall(pattern, parsed.fragment + '?' + parsed.query + '/' + parsed.path)
    if len(set(candidates)) != 1:
        raise HTTPException(422,'Vault link must identify one exact item UUID')
    return candidates[0]


def register(app, store, demo, require, agent_request):
    @app.post('/api/v1/services/{sid}/credentials/verify')
    async def verify(sid: str, body: VaultReview):
        service = require('services',sid)
        credentials = service.get('credentials',[])
        if service['revision'] != body.revision or body.index >= len(credentials):
            raise HTTPException(409,'Credential list changed; reload before checking')
        selected = item_id(credentials[body.index]['vault_ref'])
        host = require('hosts',service['host_id'])
        if not demo and (host.get('status') != 'online' or not host.get('signing_env')):
            raise HTTPException(409,'Vault existence checks require an online host with signed transport')
        result = {'status':'simulated','exists':None} if demo else await agent_request(host,'POST','/vault/check',{'item_id':selected})
        if not isinstance(result,dict) or result.get('status') not in ('exists','unverified','unavailable','simulated') or not (result.get('exists') is True or result.get('exists') is None) or (result.get('status')=='exists')!=(result.get('exists') is True):
            raise HTTPException(502,'Invalid vault verification response')
        if require('services',sid)['revision'] != body.revision:
            raise HTTPException(409,'Credential changed during verification; result discarded')
        # No returned item, credential value or session material is persisted.
        store.audit('credential.verify',result['status'],'Exact linked-item existence check; removal and credential correctness remain unverified',sid,host['id'])
        return {'status':result['status'],'exists':result.get('exists'),'checked_at':now(),'notice':'Existence only; does not verify a password, secret removal or recovery access.'}
