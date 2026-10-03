"""Stage 5 regression checks through production dispatch, never test bypasses."""
import json
import sqlite3
import pytest
from securemesh.attacks.scenarios import AttackRunner, AttackResult, mutate
from securemesh.config import Settings
from securemesh.device.commands import CommandHandler
from securemesh.device.telemetry import generate_telemetry
from securemesh.protocol import canonical_json, handshake_topic, parse_json
from securemesh.security.envelopes import encrypt_message, decrypt_message
from securemesh.security.identity import certificate_pem, generate_private_key, issue_device_certificate
from securemesh.security.sessions import _sign, SecurityError


def deliver(connected, envelope):
    connected[2].process_message('securemesh/v1/devices/device-01/telemetry', canonical_json(envelope))


def reading(connected, offset=0):
    payload = generate_telemetry()
    payload['timestamp'] = connected[4][0] + offset
    return encrypt_message(connected[0], payload, 'telemetry', now=connected[4][0])


@pytest.mark.parametrize('kind', ['ciphertext', 'header'])
@pytest.mark.parametrize('accepted', [False, True])
def test_tamper_never_advances_replay_state(connected, kind, accepted, caplog):
    envelope = reading(connected)
    if accepted:
        deliver(connected, envelope)
    before = connected[1].receive_sequence
    deliver(connected, mutate(envelope, kind))
    assert connected[3].list_security_events()[0]['event_type'] == 'invalid_authentication_tag'
    assert connected[1].receive_sequence == connected[3].list_sessions()[0]['receive_sequence'] == before
    assert len(connected[3].list_telemetry()) == int(accepted)
    for key in (connected[0].device_to_server_key, connected[0].server_to_device_key):
        assert key.hex() not in caplog.text and repr(key) not in caplog.text
    if not accepted:
        deliver(connected, envelope)
        assert connected[1].receive_sequence == 1


def test_replay_dispatch_stores_once(connected):
    envelope = reading(connected)
    deliver(connected, envelope)
    deliver(connected, envelope)
    assert len(connected[3].list_telemetry()) == 1
    assert connected[3].list_security_events()[0]['event_type'] == 'replay_attempt'
    assert connected[1].receive_sequence == 1


def test_stale_dispatch_then_fresh(connected):
    deliver(connected, reading(connected, -31000))
    assert connected[1].receive_sequence == connected[3].list_sessions()[0]['receive_sequence'] == 0
    assert connected[3].list_security_events()[0]['event_type'] == 'stale_message'
    deliver(connected, reading(connected))
    assert connected[1].receive_sequence == 2
    assert len(connected[3].list_telemetry()) == 1


@pytest.mark.parametrize('kind,code', [('unknown','unknown_device'), ('wrong_key','invalid_signature'), ('mismatch','invalid_certificate'), ('ephemeral','invalid_signature'), ('timestamp','invalid_signature')])
def test_bad_hello_creates_no_session(peers, identity, kind, code):
    client, _, center, repo, _ = peers
    hello = client.start()
    target = 'device-01'
    if kind == 'unknown':
        target = hello['device_id'] = 'device-999'
    elif kind == 'wrong_key':
        hello['signature'] = _sign(generate_private_key(), 'device-hello', canonical_json({k:v for k,v in hello.items() if k != 'signature'}))
    elif kind == 'mismatch':
        cert = issue_device_certificate('device-03', generate_private_key(), identity[0], identity[1])
        hello['certificate'] = certificate_pem(cert).decode('ascii')
    elif kind == 'ephemeral':
        hello = mutate(hello, 'ephemeral')
    else:
        hello['timestamp'] += 1
    assert center.process_message(handshake_topic(target,'hello'), canonical_json(hello)) is None
    assert code in {row['event_type'] for row in repo.list_security_events()}
    assert not center.sessions and not repo.list_sessions() and not center.handshake.pending


@pytest.mark.parametrize('field', ['transcript_hash', 'signature'])
def test_invalid_finish_never_authenticates(peers, field):
    client, _, center, repo, _ = peers
    _, response = center.process_message(handshake_topic('device-01','hello'), canonical_json(client.start()))
    finish = client.accept_response(parse_json(response))
    finish[field] = 'f'*64 if field == 'transcript_hash' else 'A'*88
    assert center.process_message(handshake_topic('device-01','finish'), canonical_json(finish)) is None
    assert not center.sessions and not repo.list_sessions()
    deliver((client.session, None, center, repo, None), {'session_id':finish['session_id']})
    assert not repo.list_telemetry()
    assert repo.list_security_events()[0]['event_type'] == 'invalid_session'


@pytest.mark.parametrize('condition', ['unauthenticated', 'unauthorized', 'tampered'])
def test_command_cannot_execute_before_auth_and_policy(connected, tmp_path, condition):
    captured=[]
    connected[2].send_command('device-01','RESTART',{},lambda t,p:captured.append(parse_json(p)))
    handler=CommandHandler(tmp_path/'state.db','device-01',lambda:connected[4][0])
    envelope=captured[0]
    if condition == 'unauthenticated': connected[0].authenticated=False
    elif condition == 'unauthorized': handler.authorized=False
    else: envelope=mutate(envelope,'ciphertext')
    try:
        ack=handler.process(connected[0],envelope)
        assert decrypt_message(connected[1],ack,'ack',now=connected[4][0])['status']=='REJECTED'
    except SecurityError:
        assert condition != 'unauthorized'
    assert handler.state['restart_count']==0
    with sqlite3.connect(handler.path) as db:
        assert db.execute('SELECT COUNT(*) FROM processed').fetchone()[0]==0


def test_duplicate_command_id_and_exact_delivery_execute_once(connected,tmp_path):
    captured=[]
    row=connected[2].send_command('device-01','RESTART',{},lambda t,p:captured.append(parse_json(p)))
    handler=CommandHandler(tmp_path/'state.db','device-01',lambda:connected[4][0])
    for index in range(3):
        ack=handler.process(connected[0],captured[0])
        connected[2].process_message('securemesh/v1/devices/device-01/acks',canonical_json(ack))
    assert handler.state['restart_count']==1
    assert connected[3].get_command(row['command_id'])['status']=='EXECUTED'
    assert sum(row['event_type']=='duplicate_command' for row in connected[3].list_security_events())==2


@pytest.mark.parametrize('path', ['telemetry','authentication','command'])
def test_revocation_admission(connected, peers, path):
    envelope=reading(connected)
    connected[2].revoke_device('device-01')
    if path == 'telemetry': deliver(connected,envelope)
    elif path == 'authentication':
        hello=peers[0].start()
        connected[2].process_message(handshake_topic('device-01','hello'),canonical_json(hello))
    else:
        with pytest.raises(SecurityError,match='revoked_device'):
            connected[2].send_command('device-01','START',{},lambda t,p:None)
    assert not connected[2].sessions
    assert all(not row['active'] for row in connected[3].list_sessions())
    assert not connected[3].list_telemetry()
    assert any('revoked_device' in row['event_type'] for row in connected[3].list_security_events())


@pytest.mark.parametrize('url,host', [('http://example.com','127.0.0.1'),('http://127.0.0.1','example.com'),('https://127.0.0.1','127.0.0.1')])
def test_actor_refuses_external_targets(url,host):
    with pytest.raises(ValueError): AttackRunner(Settings(mqtt_host=host),url)


def test_impersonation_does_not_load_victim_private_key(peers, tmp_path, monkeypatch):
    client=peers[0]
    directory=tmp_path/'devices/device-01'
    directory.mkdir(parents=True)
    (directory/'device.crt.pem').write_bytes(certificate_pem(client.certificate))
    server=tmp_path/'server.crt.pem'
    server.write_bytes(certificate_pem(client.trusted_server))
    runner=AttackRunner(Settings(runtime_dir=tmp_path,server_cert_path=server),'http://127.0.0.1')
    monkeypatch.setattr('securemesh.attacks.scenarios.load_handshake',lambda *args:pytest.fail('Victim key loaded'))
    hello=runner.attacker_hello('device-01')
    peers[2].process_message(handshake_topic('device-01','hello'),canonical_json(hello))
    assert peers[3].list_security_events()[1]['event_type']=='invalid_signature'


def test_result_allowlist_contains_no_secret_material(connected):
    result=AttackResult('REPLAY','device-01','now','BLOCKED','BLOCKED','replay_attempt',True,{},'digest',None,1,None,{})
    output=json.dumps(result.public())
    assert all(name not in output for name in ('private_key','session_key','shared_secret','BEGIN PRIVATE KEY'))
    for key in (connected[0].device_to_server_key,connected[0].server_to_device_key):
        assert key.hex() not in output and repr(key) not in output

def test_missing_event_never_reports_blocked(monkeypatch):
    runner=AttackRunner(Settings(),'http://127.0.0.1',timeout=.01)
    monkeypatch.setattr(runner,'events',lambda:[])
    monkeypatch.setattr(runner.transport,'publish',lambda *args:None)
    with pytest.raises(RuntimeError,match='timed out'):
        runner.attempt('REPLAY','device-01','topic',{},'replay_attempt')


def test_event_without_valid_evidence_never_reports_blocked(monkeypatch):
    from securemesh.attacks.scenarios import require_evidence
    runner=AttackRunner(Settings(),'http://127.0.0.1',timeout=.01)
    records=[]
    monkeypatch.setattr(runner,'events',lambda:records)
    monkeypatch.setattr(runner.transport,'publish',lambda *args:records.append({'id':1,'event_type':'replay_attempt','device_id':'device-01','session_id':None}))
    with pytest.raises(RuntimeError,match='verification failed'):
        runner.attempt('REPLAY','device-01','topic',{},'replay_attempt',lambda:require_evidence(False))
