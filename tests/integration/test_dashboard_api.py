"""Dashboard read model, exact counts, scopes and public data boundaries."""
import json
import pytest
from fastapi.testclient import TestClient
from securemesh.server.main import create_app
from securemesh.server.dashboard import event_presentation
from securemesh.security.identity import certificate_pem


def test_empty_snapshot_and_static_app(settings):
    with TestClient(create_app(settings)) as api:
        result=api.get('/api/dashboard')
        assert result.status_code==200
        data=result.json()
        assert all(value==0 for value in data['totals'].values())
        assert data['devices']==data['telemetry']==data['commands']==data['events']==[]
        page=api.get('/')
        assert 'SecureMesh' in page.text and 'script-src' in page.headers['content-security-policy']
        assert api.get('/assets/app.js').status_code==200
        assert api.get('/assets/views/commands.js').status_code==200
        assert api.get('/assets/../../runtime/ca/ca.key.pem').status_code==404


def test_exact_counts_scoped_history_and_revocation(settings,registry,identity):
    repo,service=registry
    service.register_device('device-01',certificate_pem(identity[3]))
    with repo._connection() as db:
        for sequence in range(1,151):
            db.execute('INSERT INTO telemetry (device_id,session_id,sequence,timestamp,received_at,payload) VALUES (?,?,?,?,?,?)',('device-01','a'*32,sequence,sequence,sequence,json.dumps({'temperature':25,'battery':90,'cpu_usage':5,'status':'running','timestamp':sequence})))
        for i in range(110):
            db.execute("INSERT INTO commands (command_id,device_id,command_type,parameters,issued_at,expires_at,status,session_id,sequence,created_at) VALUES (?,?,?,'{}',0,100,'EXECUTED',?,1,0)",(f'{i:032x}','device-01','START','a'*32))
    repo.record_event('replay_attempt','device-01')
    repo.record_event('session_authenticated','device-01')
    repo.record_event('unrecognized_future_event','device-01')
    with TestClient(create_app(settings)) as api:
        data=api.get('/api/dashboard?limit=3').json()
        assert data['totals']['telemetry_received']==150
        assert data['totals']['commands_issued']==data['totals']['commands_executed']==110
        assert data['totals']['blocked_events']==1
        assert len(data['telemetry'])==len(data['commands'])==3
        assert data['devices'][0]['telemetry_count']==150
        assert data['devices'][0]['latest_telemetry']['sequence']==150
        assert 'certificate' not in data['devices'][0]
        scoped=api.get('/api/dashboard?device_id=device-01&limit=2').json()
        assert scoped['scope_device_id']=='device-01'
        assert len(scoped['telemetry'])==2
        assert api.get('/api/dashboard?device_id=unknown').status_code==404
        assert api.get('/api/dashboard?device_id=bad%2B').status_code==422
        assert api.get('/api/dashboard?limit=501').status_code==422
        api.post('/api/devices/device-01/revoke')
        revoked=api.get('/api/dashboard').json()
        assert revoked['totals']['revoked_devices']==1
        assert revoked['totals']['authenticated_devices']==0
        assert revoked['devices'][0]['state']=='REVOKED' and revoked['devices'][0]['session'] is None
        assert revoked['totals']['blocked_events']==1  # Revocation itself is administrative.


@pytest.mark.parametrize('code,status',[
    ('replay_attempt','BLOCKED'),('invalid_authentication_tag','BLOCKED'),
    ('session_invalidation','ACCEPTED'),('device_revocation','ACCEPTED'),
    ('command_executed','ACCEPTED'),('command_failed','FAILED'),('unknown_future_code','INFO'),
])
def test_event_decisions_are_explicit(code,status):
    assert event_presentation(code)['status']==status


def test_live_session_counts_ignore_expiry_and_revocation(settings,registry,identity):
    from securemesh.security.sessions import now_ms
    repo,service=registry
    service.register_device('device-01',certificate_pem(identity[3]))
    with TestClient(create_app(settings)) as api:
        now=now_ms()
        with repo._connection() as db:
            db.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?)',('a'*32,'device-01',now,now+10000,7,3,1,1,'b'*64))
        data=api.get('/api/dashboard').json()
        assert data['totals']['authenticated_devices']==1
        assert data['devices'][0]['session']['receive_sequence']==7
        assert data['devices'][0]['certificate_status']=='VALID'
        with repo._connection() as db:db.execute('UPDATE sessions SET expires_at=?',(now-1,))
        data=api.get('/api/dashboard').json()
        assert data['totals']['authenticated_devices']==0 and data['devices'][0]['session'] is None
        assert data['sessions'][0]['receive_sequence']==7
        api.post('/api/devices/device-01/revoke')
        assert api.get('/api/dashboard').json()['totals']['authenticated_devices']==0
