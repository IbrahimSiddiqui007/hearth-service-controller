"""Opt-in real restic test: disposable local data only, never a NAS or service."""
import os
from pathlib import Path
import subprocess

import pytest

from agent.backups import Backups,invoke
from agent.replay import ReplayGuard
from shared.backups import AgentBackupRequest


@pytest.mark.skipif(not os.environ.get('PSC_TEST_RESTIC_BINARY'),reason='Opt-in official restic binary is not configured; mocked backup coverage still runs')
def test_real_restic_encrypted_backup_documentation_safety_and_restore(tmp_path,monkeypatch):
    binary=Path(os.environ['PSC_TEST_RESTIC_BINARY']).resolve(strict=True)
    mount=tmp_path/'synthetic-mount';mount.mkdir()
    repository=mount/'repository'
    source=tmp_path/'source';source.mkdir()
    (source/'config.yaml').write_text('value: original\n')
    state=tmp_path/'state';state.mkdir(mode=0o700)
    password='disposable-fixture-password'
    environment={k:v for k,v in os.environ.items() if not k.startswith('RESTIC_')}
    environment['RESTIC_PASSWORD']=password
    environment['RESTIC_CACHE_DIR']=str(tmp_path/'restic-test-cache')
    initialized=subprocess.run([str(binary),'--repo',str(repository),'init'],env=environment,capture_output=True,timeout=30)
    assert initialized.returncode==0,'Disposable test repository could not be initialized'
    # This is an explicitly synthetic mount acceptance boundary, not NAS evidence.
    monkeypatch.setattr('agent.backups.os.path.ismount',lambda path:path==mount)
    monkeypatch.setenv('PSC_RESTIC_FIXTURE_PASSWORD',password)
    config={'backup_profiles':{'fixture':{'storage_root':str(mount),'repository':str(repository),'paths':[str(source)],'password_env':'PSC_RESTIC_FIXTURE_PASSWORD','consistency':'static','allow_restore':True,'allow_retention':True,'runtime':{'runtime':'process','handle':{'name':'synthetic'}}}}}
    def execute(argv,env,**kwargs):return invoke([str(binary),*argv[1:]],env,**kwargs)
    observer=lambda:{'services':[{'runtime':'process','control_handle':{'name':'synthetic'},'status':'stopped'}]}
    engine=Backups(config,ReplayGuard(str(state)),execute,observer)
    fingerprint=engine.profile('fixture')['fingerprint']
    backed=engine.request(AgentBackupRequest(profile='fixture',operation_id='a'*32,action='backup',fingerprint=fingerprint,confirmed=True,documentation='# Synthetic service notebook\nReview recovery steps.'))
    selected=next(row for row in engine.plan('fixture')['snapshots'] if row['id'].startswith(backed['snapshot_id']))
    (source/'config.yaml').write_text('value: changed\n')
    (source/'extra.txt').write_text('must survive overlay')
    preview=engine.preview('fixture',selected['id'])
    assert any(row['path'].endswith('/config.yaml') for row in preview['files'])
    result=engine.request(AgentBackupRequest(profile='fixture',operation_id='b'*32,action='restore',fingerprint=fingerprint,snapshot=selected['id'],confirmed=True))
    assert (source/'config.yaml').read_text()=='value: original\n'
    assert (source/'extra.txt').read_text()=='must survive overlay'
    assert result['safety_snapshot_id']!=backed['snapshot_id']
    assert 'Synthetic service notebook' in result['documentation']
    assert len(engine.plan('fixture')['snapshots'])==2
    checked=subprocess.run([str(binary),'--repo',str(repository),'check'],env=environment,capture_output=True,timeout=30)
    assert checked.returncode==0,'Disposable restic repository integrity check failed'
