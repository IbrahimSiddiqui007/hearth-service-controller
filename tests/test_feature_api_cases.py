"""Independent valid/invalid/empty cases for public notebook/API contracts."""
import pytest
from fastapi.testclient import TestClient
from controller.app import create_app


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(tmp_path, demo=True, token='', background=False)) as c:
        yield c


@pytest.mark.parametrize('feature', ['Central dashboard','Service grid and filters','Search','Access information','Credential shortcuts','Notebook header/top banner','Living service card'])
@pytest.mark.parametrize('case', ['valid','invalid','null-edge'])
def test_public_notebook_contract(client, feature, case):
    if feature in ('Service grid and filters','Search'):
        query = 'q=25565' if case=='valid' else 'q=not-in-this-registry' if case=='invalid' else 'q='
        rows=client.get('/api/v1/services?'+query).json()
        assert [row['id'] for row in rows]==['minecraft'] if case=='valid' else rows==[] if case=='invalid' else len(rows)==8
    elif feature=='Central dashboard':
        path='/api/v1/status' if case=='valid' else '/api/v1/services/missing' if case=='invalid' else '/api/v1/services?host=absent'
        result=client.get(path)
        assert result.status_code==(404 if case=='invalid' else 200)
        if case=='valid':assert result.json()['demo'] and len(client.get('/api/v1/services').json())==8
        if case=='null-edge':assert result.json()==[]
    elif feature=='Credential shortcuts':
        service=client.get('/api/v1/services/minecraft').json()
        pointer={'label':'RCON','username':'admin','vault_ref':'https://vault.example/item'}
        rows=[pointer] if case=='valid' else [pointer|{'vault_ref':'javascript:alert(1)'}] if case=='invalid' else []
        result=client.put('/api/v1/services/minecraft/credentials',json={'revision':service['revision'],'credentials':rows})
        assert result.status_code==(422 if case=='invalid' else 200)
        if case=='valid':assert result.json()['credentials'][0]['username']=='admin'
        if case=='null-edge':assert result.json()['credentials']==[]
    elif feature=='Access information':
        manifest={'version':1,'services':[{'id':'new','host_id':'worker-node1','name':'New','runtime':'docker','urls':['http://example.invalid:8080'] if case=='valid' else ['javascript:alert(1)'] if case=='invalid' else [],'ports':['8080/tcp'] if case=='valid' else []}]}
        import json
        result=client.post('/api/v1/manifests/preview',json={'content':json.dumps(manifest)})
        assert result.status_code==(422 if case=='invalid' else 200)
    else:
        if case=='invalid':
            assert client.get('/api/v1/services/missing').status_code==404
        else:
            service=client.get('/api/v1/services/minecraft').json()
            if case=='null-edge':
                result=client.patch('/api/v1/services/minecraft',json={'revision':service['revision'],'description':'','notes':''})
                assert result.status_code==200 and result.json()['name']=='Minecraft'
            else:
                assert service['name']=='Minecraft' and service['host_name'] and service['runtime']=='compose'


@pytest.mark.parametrize('case', ['valid','invalid','null-edge'])
def test_bulk_action_scope(client,case):
    # Bulk UI uses sequential existing service controls, not a separate API.
    selected=['minecraft','ollama'] if case=='valid' else ['missing'] if case=='invalid' else []
    results=[client.post('/api/v1/services/'+sid+'/control',json={'action':'stop'}) for sid in selected]
    assert all(row.status_code==200 for row in results) if case=='valid' else results[0].status_code==404 if case=='invalid' else results==[]
    for sid in ['minecraft','ollama']:
        assert client.get('/api/v1/services/'+sid).json()['status']==('stopped' if case=='valid' else 'running')
