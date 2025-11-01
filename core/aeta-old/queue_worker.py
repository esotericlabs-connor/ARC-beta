"""Queue worker integration for Adaptive Email Threat Analysis (AETA)."""
from __future__ import annotations

import importlib
import importlib.util
import json
import logging
from typing import Any, Dict, Optional

from .core import analyze_email

LOGGER = logging.getLogger(__name__)


def _load_pika():
    if importlib.util.find_spec("pika") is None:
        raise RuntimeError("pika library is required for RabbitMQ integration")
    return importlib.import_module("pika")


class RabbitMQWorker:
    """RabbitMQ worker that consumes email metadata messages."""

    def __init__(
        self,
        amqp_url: str,
        queue_name: str,
        *,
        response_exchange: Optional[str] = None,
        response_routing_key: Optional[str] = None,
        thresholds: Optional[Dict[str, float]] = None,
    ) -> None:
        self._pika = _load_pika()
        self.amqp_url = amqp_url
        self.queue_name = queue_name
        self.response_exchange = response_exchange
        self.response_routing_key = response_routing_key
        self.thresholds = thresholds

    def start(self) -> None:
        connection = self._pika.BlockingConnection(self._pika.URLParameters(self.amqp_url))
        channel = connection.channel()
        channel.queue_declare(queue=self.queue_name, durable=True)
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue=self.queue_name, on_message_callback=self._on_message)
        LOGGER.info("AETA worker started; waiting for messages on %%s", self.queue_name)
        try:
            channel.start_consuming()
        finally:
            channel.close()
            connection.close()

    def _on_message(self, channel: Any, method: Any, properties: Any, body: bytes) -> None:
        LOGGER.debug("Processing message delivery_tag=%%s", getattr(method, "delivery_tag", None))
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            LOGGER.exception("Invalid JSON payload received")
            channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
            return

        report = analyze_email(payload, thresholds=self.thresholds)
        response_payload = json.dumps(report.to_json()).encode("utf-8")

        if self.response_exchange is not None:
            routing_key = self.response_routing_key or getattr(properties, "reply_to", "")
            channel.basic_publish(
                exchange=self.response_exchange,
                routing_key=routing_key,
                body=response_payload,
                properties=self._pika.BasicProperties(content_type="application/json"),
            )
        elif getattr(properties, "reply_to", None):
            channel.basic_publish(
                exchange="",
                routing_key=properties.reply_to,
                body=response_payload,
                properties=self._pika.BasicProperties(content_type="application/json"),
            )

        channel.basic_ack(delivery_tag=method.delivery_tag)

    def process_message(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single message payload without RabbitMQ plumbing."""

        report = analyze_email(payload, thresholds=self.thresholds)
        return report.to_json()