"""Local Stage 1 API. No MQTT, sessions or CA private-key access."""
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI

from securemesh.config import Settings
from securemesh.security.identity import load_certificate, validate_ca_certificate
from securemesh.server.repository import DeviceRepository
from securemesh.server.service import DeviceService


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Only fixed event names and explicitly selected metadata enter our logs.
        data = {"timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname, "event": record.getMessage()}
        if hasattr(record, "device_id"):
            data["device_id"] = record.device_id
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
        app.state.service = DeviceService(repository, ca_certificate)
        logging.getLogger("securemesh").info("control_center_started")
        yield

    application = FastAPI(title="SecureMesh Control Center", version="0.1.0", lifespan=lifespan)

    @application.get("/health")
    def health() -> dict:
        return {"status": "running", "service": "SecureMesh control center", "stage": 1}

    @application.get("/api/devices")
    def devices() -> list[dict]:
        return application.state.service.list_devices()

    return application


app = create_app()


def main() -> None:
    config = Settings.from_env()
    uvicorn.run(app, host=config.server_host, port=config.server_port)


if __name__ == "__main__":
    main()
