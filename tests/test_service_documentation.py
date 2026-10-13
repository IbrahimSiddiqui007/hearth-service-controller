import io
import zipfile

from fastapi.testclient import TestClient
from controller.app import create_app


def test_setup_recovery_notes_history_export_and_secret_exclusion(tmp_path):
    app = create_app(tmp_path, demo=True, token='', background=False)
    with TestClient(app) as client:
        url = '/api/v1/services/minecraft'
        original = client.get(url).json()
        first = {'installation': 'Installed from a reviewed Compose file.', 'backup_plan': 'World data copied to NAS; verify checksums.', 'recovery': 'Restore an independently verified copy before starting.'}
        saved = client.patch(url, json={'revision': original['revision'], 'documentation': first})
        assert saved.status_code == 200 and saved.json()['documentation'] == first
        assert saved.json()['notes'] == original['notes']
        second = {**first, 'recovery': 'Check configuration and world consistency, then start.'}
        saved = client.patch(url, json={'revision': saved.json()['revision'], 'documentation': second})
        assert saved.status_code == 200
        history = client.get(url + '/history').json()
        assert history['documentation'][0]['body'] == first
        assert client.get('/api/v1/services/ollama/history').json()['documentation'] == []
        assert client.patch(url, json={'revision': saved.json()['revision'], 'documentation': {'installation': 'PASSWORD=do-not-store'}}).status_code == 422
        assert 'do-not-store' not in str(app.state.store.events())
        with zipfile.ZipFile(io.BytesIO(client.get('/api/v1/export').content)) as archive:
            markdown = archive.read('docs/Service--minecraft.md').decode()
            assert '## Installation notes' in markdown and '## Backup plan' in markdown and second['recovery'] in markdown
            assert 'documentation:' in archive.read('lab.yaml').decode()
