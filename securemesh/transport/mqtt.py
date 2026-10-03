"""Bounded MQTT transport with no device authentication decisions."""
import logging
from dataclasses import dataclass
from queue import Full, Queue
from threading import Event

import paho.mqtt.client as mqtt

from securemesh.config import Settings
from securemesh.protocol import MAX_WIRE_BYTES

logger = logging.getLogger("securemesh.mqtt")


@dataclass(frozen=True)
class ReceivedMessage:
    topic: str
    payload: bytes
    retained: bool


class MQTTTransport:
    def __init__(self, settings: Settings, client_id: str, subscriptions: list[str]):
        self.settings, self.subscriptions = settings, subscriptions
        self.messages: Queue[ReceivedMessage] = Queue(maxsize=256)
        self.connected = Event()
        self.generation = 0
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id,
                                  clean_session=True, protocol=mqtt.MQTTv311)
        self.client.max_queued_messages_set(256)
        self.client.reconnect_delay_set(min_delay=1, max_delay=10)
        if settings.mqtt_username:
            self.client.username_pw_set(settings.mqtt_username, settings.mqtt_password)
        self.client.on_connect = self._on_connect
        self.client.on_subscribe = self._on_subscribe
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, reason_code, properties) -> None:
        if reason_code.is_failure:
            logger.warning("mqtt_connection_rejected")
            return
        self.generation += 1
        if self.subscriptions:
            client.subscribe([(topic, 1) for topic in self.subscriptions])
        else:
            self.connected.set()
        logger.info("mqtt_connected")

    def _on_subscribe(self, client, userdata, mid, reason_codes, properties) -> None:
        if any(code.is_failure for code in reason_codes):
            logger.warning("mqtt_subscription_rejected")
        else:
            # Wait for SUBACK before publishing a hello, avoiding a response race.
            self.connected.set()

    def _on_disconnect(self, client, userdata, flags, reason_code, properties) -> None:
        self.connected.clear()
        logger.info("mqtt_disconnected")

    def _on_message(self, client, userdata, message) -> None:
        if len(message.payload) > MAX_WIRE_BYTES:
            logger.warning("mqtt_message_too_large")
            return
        try:
            self.messages.put_nowait(ReceivedMessage(message.topic, bytes(message.payload), bool(message.retain)))
        except Full:
            logger.warning("mqtt_queue_full")

    def start(self, timeout: float = 10) -> None:
        self.client.connect_async(self.settings.mqtt_host, self.settings.mqtt_port, keepalive=15)
        self.client.loop_start()
        if not self.connected.wait(timeout):
            self.stop()
            raise ConnectionError("MQTT connection/subscription timed out")

    def publish(self, topic: str, payload: bytes) -> None:
        if len(payload) > MAX_WIRE_BYTES:
            raise ValueError("Message exceeds wire size limit")
        if not self.connected.is_set():
            raise ConnectionError("MQTT is disconnected")
        result = self.client.publish(topic, payload, qos=1, retain=False)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise ConnectionError("MQTT publish failed")
        result.wait_for_publish(timeout=5)
        if not result.is_published():
            raise ConnectionError("MQTT publish acknowledgement timed out")

    def stop(self) -> None:
        self.client.disconnect()
        self.client.loop_stop()
        self.connected.clear()
