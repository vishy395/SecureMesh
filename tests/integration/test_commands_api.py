"""API input validation and lifecycle behavior without requiring a broker."""
import pytest
from fastapi.testclient import TestClient
from securemesh.server.main import create_app
from securemesh.security.identity import certificate_pem

@pytest.mark.parametrize('body',[
    {'command_type':'START','parameters':{},'shell':'bad'},
    {'command_type':1,'parameters':{}},
    {'command_type':'START','parameters':[]},
    {'command_type':'START'},
])
def test_command_request_schema(settings,body):
    with TestClient(create_app(settings)) as client:
        assert client.post('/api/devices/device-01/commands',json=body).status_code==422

def test_revocation_registry_mode(settings,registry,identity):
    repo,service=registry
    service.register_device('device-01',certificate_pem(identity[3]))
    with TestClient(create_app(settings)) as client:
        assert client.post('/api/devices/device-01/revoke').json()['state']=='REVOKED'
        assert client.get('/api/devices').json()[0]['state']=='REVOKED'
        assert client.post('/api/devices/unknown/revoke').status_code==404
        assert client.get('/api/commands').json()==[]
        assert client.post('/api/devices/device-01/commands',json={'command_type':'START','parameters':{}}).status_code==409
        assert any(row['event_type']=='device_revocation' for row in repo.list_security_events())

@pytest.mark.parametrize('body',[
    {'command_type':'SHELL','parameters':{}},
    {'command_type':'START','parameters':{'shell':'bad'}},
    {'command_type':'CHANGE_THRESHOLD','parameters':{'threshold':True}},
    {'command_type':'CHANGE_THRESHOLD','parameters':{'threshold':10**400}},
    {'command_type':'UPDATE_CONFIG','parameters':{'telemetry_interval':10**400}},
    {'command_type':'UPDATE_CONFIG','parameters':{'server_key':'bad'}},
])
def test_command_policy_validates_before_transport(settings,body):
    with TestClient(create_app(settings)) as client:
        assert client.post('/api/devices/device-01/commands',json=body).status_code==422
        assert client.get('/api/security-events').json()[0]['event_type'] in {'invalid_parameters','unsupported_command'}


def test_unknown_target_and_unavailable_transport(settings,registry,identity):
    registry[1].register_device('device-01',certificate_pem(identity[3]))
    with TestClient(create_app(settings)) as client:
        body={'command_type':'START','parameters':{}}
        assert client.post('/api/devices/unknown/commands',json=body).status_code==404
        assert client.post('/api/devices/device-01/commands',json=body).status_code==503
