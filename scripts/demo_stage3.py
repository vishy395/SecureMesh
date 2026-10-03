"""Fixed Stage 3 operator demonstration against three running simulators.

Run only against disposable registrations: this demo revokes device-02.
"""
import argparse
import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from securemesh.config import Settings
from securemesh.protocol import MessageType, device_topic
from securemesh.transport.mqtt import MQTTTransport


def run(url: str) -> None:
    def api(path, body=None):
        request = Request(url + path, data=json.dumps(body).encode() if body is not None else None,
                          headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return json.load(response)

    def wait_for(predicate, description, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                print(description)
                return
            time.sleep(0.1)
        raise RuntimeError("Demo condition timed out: " + description)

    observer = MQTTTransport(Settings.from_env(), "securemesh-stage3-demo", [
        "securemesh/v1/devices/+/commands",
    ])
    try:
        observer.start()
        wait_for(lambda: {row['device_id'] for row in api('/api/telemetry')} >=
                 {'device-01', 'device-02', 'device-03'}, "All three devices sent authenticated telemetry")
        sessions = {row['device_id']: row['session_id'] for row in api('/api/sessions') if row['active']}
        if not {'device-01', 'device-02', 'device-03'} <= sessions.keys():
            raise RuntimeError("All three devices need active sessions")
        commands = {}
        for device_id, kind, parameters in [
            ('device-01', 'START', {}),
            ('device-02', 'CHANGE_THRESHOLD', {'threshold': 35.0}),
            ('device-03', 'STOP', {}),
        ]:
            commands[device_id] = api(f'/api/devices/{device_id}/commands', {
                'command_type': kind, 'parameters': parameters,
            })
        identifiers = {row['command_id'] for row in commands.values()}
        wait_for(lambda: identifiers <= {row['command_id'] for row in api('/api/commands')
                 if row['status'] == 'EXECUTED'}, "START / CHANGE_THRESHOLD / STOP acknowledged")
        captured = [observer.messages.get(timeout=5) for _ in range(3)]
        duplicate = next(message for message in captured if message.topic == device_topic('device-03', MessageType.COMMAND))
        baseline = sum(row['event_type'] == 'duplicate_command' and row['device_id'] == 'device-03'
                       for row in api('/api/security-events'))
        observer.publish(duplicate.topic, duplicate.payload)
        observer.publish(duplicate.topic, duplicate.payload)
        wait_for(lambda: sum(row['event_type'] == 'duplicate_command' and row['device_id'] == 'device-03'
                 for row in api('/api/security-events')) >= baseline + 2,
                 "Two redeliveries acknowledged as ALREADY_PROCESSED")
        api('/api/devices/device-02/revoke', {})
        assert all(not row['active'] for row in api('/api/sessions') if row['device_id'] == 'device-02')
        try:
            api('/api/devices/device-02/commands', {'command_type': 'START', 'parameters': {}})
        except HTTPError as exc:
            if exc.code != 409 or json.load(exc).get('detail') != 'revoked_device':
                raise
        else:
            raise RuntimeError('Revoked command unexpectedly accepted')
        wait_for(lambda: any(row['device_id'] == 'device-02' and row['event_type'] == 'revoked_device'
                 for row in api('/api/security-events')), "Revoked device telemetry rejected; commands rejected; sessions invalid")
        rows = api('/api/telemetry')
        latest = {device_id: max(row['id'] for row in rows if row['device_id'] == device_id)
                  for device_id in ('device-01', 'device-02', 'device-03')}
        wait_for(lambda: all(any(row['device_id'] == device_id and row['id'] > latest[device_id]
                 for row in api('/api/telemetry')) for device_id in ('device-01', 'device-03')),
                 "device-01 and device-03 continue operating")
        assert not any(row['device_id'] == 'device-02' and row['id'] > latest['device-02']
                       for row in api('/api/telemetry'))
    finally:
        observer.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8000')
    args = parser.parse_args()
    try:
        run(args.url.rstrip('/'))
    except (HTTPError, URLError, RuntimeError, ConnectionError) as exc:
        # Fixed failure output; HTTP bodies and transport credentials stay private.
        raise SystemExit('Stage 3 demo failed; check services and active disposable registrations') from exc


if __name__ == '__main__':
    main()
