"""Software simulator: authenticated sessions and encrypted telemetry only."""
import argparse
import logging
import math
import secrets
import time
from queue import Empty

from securemesh.config import Settings
from securemesh.device.state import load_handshake
from securemesh.device.telemetry import generate_telemetry
from securemesh.protocol import MessageType, canonical_json, device_topic, handshake_topic, parse_json
from securemesh.security.envelopes import accept_ready, encrypt_message
from securemesh.security.identity import IdentityError
from securemesh.security.sessions import SecurityError, now_ms
from securemesh.server.main import configure_logging
from securemesh.transport.mqtt import MQTTTransport

logger = logging.getLogger("securemesh.device")


def run_device(settings: Settings, device_id: str, interval: float, count: int = 0) -> None:
    handshake = load_handshake(settings, device_id)
    transport = MQTTTransport(settings, f"securemesh-{device_id}-{secrets.token_hex(4)}", [
        handshake_topic(device_id, "response"), handshake_topic(device_id, "ready")])
    session = None
    generation = 0
    deadline = 0.0
    next_send = 0.0
    sent = 0

    def publish(topic: str, payload: bytes) -> bool:
        try:
            transport.publish(topic, payload)
            return True
        except (ConnectionError, RuntimeError):
            logger.warning("device_publish_failed", extra={"device_id": device_id})
            return False

    try:
        transport.start()
        while count == 0 or sent < count:
            monotonic = time.monotonic()
            if not transport.connected.is_set():
                session = None
                time.sleep(0.1)
                continue
            if generation != transport.generation:
                generation = transport.generation
                session = None
                deadline = 0
                # Old queued replies cannot confirm a new hello transcript.
                while not transport.messages.empty():
                    try:
                        transport.messages.get_nowait()
                    except Empty:
                        break
            if session and (now_ms() >= session.expires_at or session.send_sequence >= session.max_messages):
                session = None
                deadline = 0
            if session is None and monotonic >= deadline:
                hello = handshake.start()
                if not publish(handshake_topic(device_id, "hello"), canonical_json(hello)):
                    deadline = monotonic + 1
                    continue
                deadline = monotonic + settings.handshake_ttl_seconds
                logger.info("device_handshake_started", extra={"device_id": device_id})
            try:
                incoming = transport.messages.get(timeout=0.05)
                if incoming.retained:
                    raise SecurityError("retained_message_rejected")
                message = parse_json(incoming.payload)
                if incoming.topic == handshake_topic(device_id, "response") and session is None:
                    finish = handshake.accept_response(message)
                    publish(handshake_topic(device_id, "finish"), canonical_json(finish))
                elif incoming.topic == handshake_topic(device_id, "ready") and session is None:
                    if handshake.session is None:
                        raise SecurityError("invalid_session")
                    accept_ready(handshake.session, message)
                    session = handshake.session
                    next_send = monotonic
                    logger.info("device_authenticated", extra={"device_id": device_id, "session_id": session.session_id})
            except Empty:
                pass
            except SecurityError as exc:
                logger.warning(exc.code, extra={"device_id": device_id})
            except IdentityError:
                logger.warning("invalid_certificate", extra={"device_id": device_id})
            except (ValueError, TypeError, KeyError, AttributeError):
                # Do not let a forged response force a counter reset or restart.
                logger.warning("device_handshake_rejected", extra={"device_id": device_id})
            if session and time.monotonic() >= next_send:
                envelope = encrypt_message(session, generate_telemetry(), "telemetry")
                if not publish(device_topic(device_id, MessageType.TELEMETRY), canonical_json(envelope)):
                    # The old counter is burned. Recovery uses entirely new session keys.
                    session = None
                    deadline = 0
                    continue
                sent += 1
                next_send = time.monotonic() + interval
                logger.info("telemetry_published", extra={"device_id": device_id,
                            "session_id": session.session_id, "sequence": envelope["sequence"]})
    finally:
        transport.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--count", type=int, default=0, help="Stop after N messages; 0 means continuous")
    args = parser.parse_args()
    if not math.isfinite(args.interval) or args.interval <= 0 or args.count < 0:
        parser.error("Interval must be positive and finite; count must be nonnegative")
    configure_logging()
    try:
        run_device(Settings.from_env(), args.device_id, args.interval, args.count)
    except KeyboardInterrupt:
        logger.info("device_stopped")
    except (IdentityError, ValueError, OSError, ConnectionError, RuntimeError):
        logger.error("device_failed")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
