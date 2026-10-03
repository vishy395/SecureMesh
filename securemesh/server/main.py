"""Local control center with optional secure MQTT telemetry. No CA key access."""
import json
import logging
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from queue import Empty
from threading import Event, Thread

import uvicorn
from fastapi import FastAPI

from securemesh.config import Settings
from securemesh.security.identity import load_certificate, load_private_key, validate_ca_certificate, validate_server_certificate
from securemesh.server.repository import DeviceRepository
from securemesh.server.service import DeviceService, TelemetryService
from securemesh.transport.mqtt import MQTTTransport
from securemesh.protocol import TOPIC_PREFIX


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Only fixed event names and explicitly selected metadata enter our logs.
        data = {"timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname, "event": record.getMessage()}
        for name in ("device_id", "session_id", "sequence"):
            if hasattr(record, name):
                data[name] = getattr(record, name)
        return json.dumps(data)


def configure_logging() -> None:
    logger = logging.getLogger("securemesh")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging()
        config = settings or Settings.from_env()
        # This trust anchor is public. No server code reads the CA private key.
        ca_certificate = load_certificate(config.ca_cert_path.read_bytes())
        validate_ca_certificate(ca_certificate)
        repository = DeviceRepository(config.database_path)
        repository.initialize()
        repository.invalidate_sessions()
        app.state.service = DeviceService(repository, ca_certificate)
        stop = Event()
        transport = None
        telemetry_service = None
        worker = None
        if config.mqtt_enabled:
            server_certificate = load_certificate(config.server_cert_path.read_bytes())
            validate_server_certificate(server_certificate, ca_certificate, config.server_identity)
            server_key = load_private_key(config.server_key_path)
            if server_key.public_key().public_bytes_raw() != server_certificate.public_key().public_bytes_raw():
                raise ValueError("Server key does not match server certificate")
            telemetry_service = TelemetryService(config, app.state.service, server_key, server_certificate)
            transport = MQTTTransport(config, "securemesh-control-center", [
                f"{TOPIC_PREFIX}/+/handshake/hello", f"{TOPIC_PREFIX}/+/handshake/finish",
                f"{TOPIC_PREFIX}/+/telemetry"])
            transport.start()

            def receive() -> None:
                while not stop.is_set():
                    try:
                        message = transport.messages.get(timeout=0.25)
                        reply = telemetry_service.process_message(message.topic, message.payload, retained=message.retained)
                        if reply:
                            transport.publish(*reply)
                    except Empty:
                        pass
                    except (ConnectionError, OSError, RuntimeError, sqlite3.Error):
                        logging.getLogger("securemesh").warning("mqtt_processing_failed")
                    try:
                        telemetry_service.prune()
                    except sqlite3.Error:
                        logging.getLogger("securemesh").warning("session_cleanup_failed")

            worker = Thread(target=receive, name="securemesh-telemetry", daemon=True)
            worker.start()
        app.state.transport = transport
        logging.getLogger("securemesh").info("control_center_started")
        try:
            yield
        finally:
            stop.set()
            if worker:
                worker.join(timeout=10)
            if transport:
                transport.stop()
            if telemetry_service:
                telemetry_service.shutdown()

    application = FastAPI(title="SecureMesh Control Center", version="0.1.0", lifespan=lifespan)

    @application.get("/health")
    def health() -> dict:
        transport = application.state.transport
        return {"status": "running", "service": "SecureMesh control center", "stage": 2,
                "mqtt": "connected" if transport and transport.connected.is_set() else "disconnected" if transport else "disabled"}

    @application.get("/api/devices")
    def devices() -> list[dict]:
        return application.state.service.list_devices()

    @application.get("/api/telemetry")
    def telemetry() -> list[dict]:
        return application.state.service.repository.list_telemetry()

    @application.get("/api/security-events")
    def security_events() -> list[dict]:
        return application.state.service.repository.list_security_events()

    @application.get("/api/sessions")
    def sessions() -> list[dict]:
        return application.state.service.repository.list_sessions()

    return application


app = create_app()


def main() -> None:
    config = Settings.from_env()
    uvicorn.run(app, host=config.server_host, port=config.server_port)


if __name__ == "__main__":
    main()
