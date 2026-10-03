"""Stage 3 validates security before any durable simulated effect."""
import sqlite3
import pytest
from securemesh.device.commands import CommandHandler
from securemesh.protocol import canonical_json, parse_json, device_topic, MessageType
from securemesh.security.envelopes import encrypt_message, decrypt_message
from securemesh.security.sessions import SecurityError
from securemesh.commands import validate_parameters

@pytest.fixture
def handler(tmp_path, connected):
    return CommandHandler(tmp_path/'state.db','device-01',lambda:connected[4][0])

def issue(connected, kind='START', parameters=None):
    captured=[]
    row=connected[2].send_command('device-01',kind,parameters or {},lambda t,p:captured.append((t,p)))
    return row,parse_json(captured[0][1])

def crafted(connected, **changes):
    server=connected[1]
    now=connected[4][0]
    payload={'version':1,'command_id':'a'*32,'target_device_id':'device-01','command_type':'START','parameters':{},'issued_at':now,'expires_at':now+20000,'session_id':server.session_id,'sequence':server.send_sequence+1}
    payload.update(changes)
    return encrypt_message(server,payload,'command',now=now)

@pytest.mark.parametrize('kind,params,field,value',[
    ('START',{},'state','RUNNING'),('STOP',{},'state','STOPPED'),
    ('RESTART',{},'restart_count',1),('CHANGE_THRESHOLD',{'threshold':40.0},'threshold',40.0),
    ('UPDATE_CONFIG',{'telemetry_interval':0.2,'location_enabled':False},'configuration',{'telemetry_interval':0.2,'location_enabled':False})])
def test_valid_commands(connected,handler,kind,params,field,value):
    row,envelope=issue(connected,kind,params)
    ack=handler.process(connected[0],envelope)
    connected[2].accept_ack('device-01',ack)
    assert handler.state[field]==value
    assert connected[3].get_command(row['command_id'])['status']=='EXECUTED'

@pytest.mark.parametrize('deliveries',[2,3,10])
def test_exact_mqtt_redelivery_executes_once(connected,handler,deliveries):
    row,envelope=issue(connected,'RESTART')
    for index in range(deliveries):
        ack=handler.process(connected[0],envelope)
        payload=decrypt_message(connected[1],ack,'ack',now=connected[4][0])
        assert payload['status']==('EXECUTED' if index==0 else 'ALREADY_PROCESSED')
        connected[2].accept_ack('device-01',ack)
    assert handler.state['restart_count']==1
    assert connected[3].get_command(row['command_id'])['status']=='EXECUTED'

def test_dedup_survives_handler_restart(connected,handler):
    _,envelope=issue(connected,'RESTART')
    handler.process(connected[0],envelope)
    restored=CommandHandler(handler.path,'device-01',handler.clock)
    ack=restored.process(connected[0],envelope)
    assert decrypt_message(connected[1],ack,'ack',now=handler.clock())['status']=='ALREADY_PROCESSED'
    assert restored.state['restart_count']==1

def test_same_id_fresh_envelope_and_redelivery(connected,handler):
    envelope=crafted(connected,command_type='RESTART')
    handler.process(connected[0],envelope)
    second=crafted(connected,command_type='RESTART')
    for wire in [second,second]:
        ack=handler.process(connected[0],wire)
        assert decrypt_message(connected[1],ack,'ack',now=handler.clock())['status']=='ALREADY_PROCESSED'
    assert handler.state['restart_count']==1

@pytest.mark.parametrize('changes',[
    {'target_device_id':'device-02'}, {'session_id':'f'*32}, {'command_id':'../bad'},
    {'version':2}, {'expires_at':0}, {'sequence':0}, {'issued_at':0},
    {'command_type':'SHELL'}, {'parameters':{'unexpected':True}},
    {'command_type':'CHANGE_THRESHOLD','parameters':{'threshold':True}},
    {'command_type':'UPDATE_CONFIG','parameters':{'shell':'rm'}},
])
def test_invalid_authenticated_command_no_effect(connected,handler,changes):
    envelope=crafted(connected,**changes)
    before=handler.state
    try:
        ack=handler.process(connected[0],envelope)
    except SecurityError:
        pass
    else:
        assert decrypt_message(connected[1],ack,'ack',now=handler.clock())['status']=='REJECTED'
    assert handler.state==before
    with sqlite3.connect(handler.path) as db:
        assert db.execute('SELECT COUNT(*) FROM processed').fetchone()[0]==0

@pytest.mark.parametrize('field,value',[
    ('ciphertext','AAAAAAAAAAAAAAAAAAAAAA=='),('nonce','AAAAAAAAAAAAAAAA'),
    ('device_id','device-02'),('session_id','f'*32),('direction','device_to_server'),
    ('sequence',0),('version',2),('message_type','telemetry')])
def test_modified_command_rejected_before_effect(connected,handler,field,value):
    _,envelope=issue(connected,'RESTART')
    envelope[field]=value
    with pytest.raises((SecurityError,ValueError)):
        handler.process(connected[0],envelope)
    assert handler.state['restart_count']==0
    assert connected[0].receive_sequence==1

def test_ciphertext_modified_duplicate_not_acknowledged(connected,handler):
    _,envelope=issue(connected,'RESTART')
    handler.process(connected[0],envelope)
    envelope['ciphertext']='AAAAAAAAAAAAAAAAAAAAAA=='
    with pytest.raises(SecurityError,match='invalid_authentication_tag'):
        handler.process(connected[0],envelope)
    assert handler.state['restart_count']==1

def test_application_id_conflict(connected,handler):
    handler.process(connected[0],crafted(connected))
    with pytest.raises(SecurityError,match='command_id_conflict'):
        handler.process(connected[0],crafted(connected,command_type='STOP'))
    assert handler.state['state']=='RUNNING'

@pytest.mark.parametrize('kind,params',[
    ('CHANGE_THRESHOLD',{'threshold':float('nan')}),('CHANGE_THRESHOLD',{'threshold':'35'}),
    ('CHANGE_THRESHOLD',{'threshold':201}),('UPDATE_CONFIG',{}),
    ('UPDATE_CONFIG',{'telemetry_interval':0}),('UPDATE_CONFIG',{'location_enabled':1}),
    ('UPDATE_CONFIG',{'private_key':'abc'}),('START',{'x':1}),('SHELL',{}),('START',[])])
def test_policy_rejects_invalid_input(kind,params):
    with pytest.raises(SecurityError): validate_parameters(kind,params)

def test_revocation_invalidates_and_rejects_every_path(connected,handler):
    from securemesh.device.telemetry import generate_telemetry
    client,server,center,repo,clock=connected
    pending=encrypt_message(client,generate_telemetry(),'telemetry',now=clock[0])
    center.revoke_device('device-01')
    assert not server.authenticated
    assert all(row['active']==0 for row in repo.list_sessions())
    with pytest.raises(SecurityError,match='revoked_device'): center.accept_telemetry('device-01',pending)
    with pytest.raises(SecurityError,match='revoked_device'): center.send_command('device-01','START',{},lambda *args:None)
    with pytest.raises(SecurityError,match='revoked_device'): center._validate_device('device-01',repo.get_device('device-01')['certificate'].encode())
    with pytest.raises(SecurityError): decrypt_message(server,pending,'telemetry',now=clock[0])

def test_expired_session(connected,handler):
    _,envelope=issue(connected)
    connected[4][0]=connected[0].expires_at
    with pytest.raises(SecurityError,match='expired_session'): handler.process(connected[0],envelope)
    connected[2].prune()
    assert connected[3].list_sessions()[0]['active']==0

def test_explicit_rotation(connected):
    client,server,center,repo,clock=connected
    captured=[]
    center.rotate_session('device-01',lambda t,p:captured.append(parse_json(p)))
    assert decrypt_message(client,captured[0],'session_control',now=clock[0])['action']=='rotate'
    assert not server.authenticated
    assert not center.sessions
    assert repo.list_sessions()[0]['active']==0

def test_individual_session_invalidation(connected):
    connected[2].invalidate_session(connected[1].session_id)
    assert not connected[1].authenticated
    assert connected[3].list_sessions()[0]['active']==0

@pytest.mark.parametrize('change',[
    {'device_id':'device-02'}, {'command_id':'b'*32}, {'command_sequence':999},
    {'status':'anything'}, {'timestamp':0}, {'version':2}])
def test_forged_ack_cannot_update_command(connected,change):
    row,_=issue(connected)
    payload={'version':1,'command_id':row['command_id'],'device_id':'device-01','status':'EXECUTED','timestamp':connected[4][0],'command_sequence':row['sequence']}
    payload.update(change)
    envelope=encrypt_message(connected[0],payload,'ack',now=connected[4][0])
    with pytest.raises((SecurityError,ValueError)): connected[2].accept_ack('device-01',envelope)
    assert connected[3].get_command(row['command_id'])['status']=='SENT'
    assert connected[1].receive_sequence==0

def test_tampered_ack(connected,handler):
    row,envelope=issue(connected)
    ack=handler.process(connected[0],envelope)
    ack['ciphertext']='AAAAAAAAAAAAAAAAAAAAAA=='
    with pytest.raises(SecurityError): connected[2].accept_ack('device-01',ack)
    assert connected[3].get_command(row['command_id'])['status']=='SENT'

def test_command_expires_without_ack(connected):
    row,_=issue(connected)
    connected[4][0]=row['expires_at']
    connected[2].prune()
    assert connected[3].get_command(row['command_id'])['status']=='EXPIRED'

def test_publish_failure_preserves_command_metadata_and_burns_counter(connected):
    def fail(*args): raise ConnectionError()
    sequence=connected[1].send_sequence
    with pytest.raises(SecurityError,match='command_publish_failed'):
        connected[2].send_command('device-01','START',{},fail)
    assert connected[1].send_sequence==sequence+1
    assert connected[3].list_commands()[0]['status']=='FAILED'

def test_device_authorization_boundary(connected,handler):
    _,envelope=issue(connected)
    handler.authorized=False
    ack=handler.process(connected[0],envelope)
    connected[2].accept_ack('device-01',ack)
    assert connected[3].list_commands()[0]['status']=='REJECTED'
    assert handler.state['last_command'] is None

def test_rotation_fresh_keys_and_old_messages_rejected(peers):
    from securemesh.protocol import handshake_topic
    from securemesh.security.envelopes import accept_ready
    from securemesh.device.telemetry import generate_telemetry
    client,_,center,repo,clock=peers
    sessions=[]
    ephemerals=[]
    responses=[]
    old_wire=None
    for _ in range(2):
        hello=client.start()
        ephemerals.append(hello['device_ephemeral'])
        _,wire=center.process_message(handshake_topic('device-01','hello'),canonical_json(hello))
        response=parse_json(wire)
        responses.append(response['server_ephemeral'])
        finish=client.accept_response(response)
        _,ready=center.process_message(handshake_topic('device-01','finish'),canonical_json(finish))
        from securemesh.security.envelopes import accept_ready
        accept_ready(client.session,parse_json(ready),now=clock[0])
        sessions.append(client.session)
        if old_wire is None: old_wire=encrypt_message(client.session,generate_telemetry(),'telemetry',now=clock[0])
    assert ephemerals[0]!=ephemerals[1] and responses[0]!=responses[1]
    assert sessions[0].device_to_server_key!=sessions[1].device_to_server_key
    assert sessions[0].server_to_device_key!=sessions[1].server_to_device_key
    assert not sessions[0].authenticated
    assert len(center.sessions)==1
    with pytest.raises(SecurityError,match='invalid_session'): center.accept_telemetry('device-01',old_wire)
    assert sorted(row['active'] for row in repo.list_sessions())==[0,1]

def test_revoked_device_new_hello_rejected(peers):
    from securemesh.protocol import handshake_topic
    client,_,center,repo,_=peers
    center.revoke_device('device-01')
    assert center.process_message(handshake_topic('device-01','hello'),canonical_json(client.start())) is None
    assert not center.handshake.pending
    assert any(row['event_type']=='revoked_device' for row in repo.list_security_events())

def test_message_limit_prevents_nonce_reuse(connected):
    server=connected[1]
    server.max_messages=server.send_sequence+1
    issue(connected)
    with pytest.raises(SecurityError,match='session_message_limit'): issue(connected)
    assert len(connected[3].list_commands())==1

def test_cross_device_ciphertext_rejected(connected,handler):
    _,wire=issue(connected,'RESTART')
    other=CommandHandler(handler.path.parent/'other.db','device-02',handler.clock)
    with pytest.raises(SecurityError,match='wrong_target_device'): other.process(connected[0],wire)
    assert other.state['restart_count']==0

def test_no_keys_in_persistence_or_public_metadata(connected,handler):
    row,wire=issue(connected)
    connected[2].accept_ack('device-01',handler.process(connected[0],wire))
    dump=canonical_json({'sessions':connected[3].list_sessions(),'commands':connected[3].list_commands(),'events':connected[3].list_security_events()})
    for key in [connected[0].device_to_server_key,connected[0].server_to_device_key]:
        import base64
        assert key not in dump and base64.b64encode(key) not in dump and key.hex().encode() not in dump
        assert key not in handler.path.read_bytes()
    assert connected[3].get_session(row['session_id'])['send_sequence']==wire['sequence']

def test_persisted_session_invalidation_blocks_commands(connected):
    connected[3].invalidate_sessions(connected[1].session_id)
    with pytest.raises(SecurityError,match='invalid_session'): issue(connected)

def test_storage_failure_acknowledged_without_execution(connected,handler,monkeypatch):
    row,wire=issue(connected,'RESTART')
    def fail(*args): raise sqlite3.OperationalError('sanitized outside the protocol')
    monkeypatch.setattr(handler,'_execute',fail)
    connected[2].accept_ack('device-01',handler.process(connected[0],wire))
    assert connected[3].get_command(row['command_id'])['status']=='FAILED'
    assert handler.state['restart_count']==0


def test_authenticated_unknown_replay_not_executed(connected,handler):
    wire=crafted(connected,command_type='RESTART')
    connected[0].receive_sequence=wire['sequence']
    with pytest.raises(SecurityError,match='replay_attempt'): handler.process(connected[0],wire)
    assert handler.state['restart_count']==0


def test_three_devices_sessions_and_revocation_isolation(peers,identity,settings,tmp_path):
    from securemesh.security.sessions import DeviceHandshake
    from securemesh.security.identity import generate_private_key,issue_device_certificate,certificate_pem
    from securemesh.security.envelopes import accept_ready
    from securemesh.protocol import handshake_topic
    from securemesh.device.telemetry import generate_telemetry
    original,_,center,repo,clock=peers
    clients={'device-01':original}
    handlers={}
    for device_id in ['device-02','device-03']:
        key=generate_private_key()
        cert=issue_device_certificate(device_id,key,identity[0],identity[1])
        center.registry.register_device(device_id,certificate_pem(cert))
        clients[device_id]=DeviceHandshake(settings,device_id,key,cert,identity[1],original.trusted_server,lambda:clock[0])
    for device_id,client in clients.items():
        _,response=center.process_message(handshake_topic(device_id,'hello'),canonical_json(client.start()))
        finish=client.accept_response(parse_json(response))
        _,ready=center.process_message(handshake_topic(device_id,'finish'),canonical_json(finish))
        accept_ready(client.session,parse_json(ready),now=clock[0])
        reading=generate_telemetry()
        reading['timestamp']=clock[0]
        center.accept_telemetry(device_id,encrypt_message(client.session,reading,'telemetry',now=clock[0]))
        handlers[device_id]=CommandHandler(tmp_path/device_id/'state.db',device_id,lambda:clock[0])
    for device_id,kind,params in [('device-01','START',{}),('device-02','CHANGE_THRESHOLD',{'threshold':35.0}),('device-03','STOP',{})]:
        captured=[]
        row=center.send_command(device_id,kind,params,lambda t,p:captured.append(parse_json(p)))
        for other in clients:
            if other!=device_id:
                with pytest.raises(SecurityError): handlers[other].process(clients[other].session,captured[0])
        ack=handlers[device_id].process(clients[device_id].session,captured[0])
        center.accept_ack(device_id,ack)
        assert repo.get_command(row['command_id'])['status']=='EXECUTED'
    assert handlers['device-03'].state['state']=='STOPPED'
    assert handlers['device-01'].state['state']=='RUNNING'
    center.revoke_device('device-02')
    with pytest.raises(SecurityError,match='revoked_device'): center.send_command('device-02','START',{},lambda *args:None)
    for device_id,client in clients.items():
        reading=generate_telemetry()
        reading['timestamp']=clock[0]
        wire=encrypt_message(client.session,reading,'telemetry',now=clock[0])
        if device_id=='device-02':
            with pytest.raises(SecurityError,match='revoked_device'): center.accept_telemetry(device_id,wire)
        else:
            center.accept_telemetry(device_id,wire)
    assert len(repo.list_telemetry())==5
    assert len(center.sessions)==2


def test_external_revocation_removes_live_session_on_maintenance(connected):
    client,server,center,repo,_=connected
    center.registry.revoke_device('device-01')
    center.prune()
    assert not center.sessions and not server.authenticated
    assert repo.get_session(client.session_id)['active']==0
    assert any(row['event_type']=='session_invalidation' for row in repo.list_security_events())


def test_session_commit_checks_final_revocation_state(connected):
    from securemesh.server.repository import RegistryError
    connected[3].revoke_device('device-01')
    with pytest.raises(RegistryError,match='Device changed'):
        connected[3].create_session(connected[1])
    assert connected[3].list_sessions()[0]['active']==0
