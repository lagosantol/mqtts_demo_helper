# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""AMQTT event plugin that echoes accepted device messages after a delay."""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from amqtt.broker import BrokerContext
from amqtt.plugins.base import BasePlugin

from mqtt_demo.logging_utils import log_category
from mqtt_demo.models import Mode
from mqtt_demo.topics import topics_for

LOGGER = logging.getLogger(__name__)


class BrokerEventPlugin(BasePlugin[BrokerContext]):
    """Log broker lifecycle events and schedule topic-mapped echoes."""

    @dataclass
    class Config:
        mode: str = "generic"
        echo_delay: float = 3.0

    def __init__(self, context: BrokerContext) -> None:
        super().__init__(context)
        self.mode = Mode(self._get_config_option("mode", "generic"))
        self.echo_delay = float(self._get_config_option("echo-delay", 3.0))
        self._echo_tasks: set[asyncio.Task[None]] = set()

    async def on_broker_client_connected(self, *, client_id: str, client_session: Any) -> None:
        log_category(
            LOGGER,
            "MQTT",
            "CONNECTED identity=%s ClientId=%s Timestamp=%s",
            client_session.attributes.get("mqtt_demo.identity", "unknown"),
            client_id,
            datetime.now(timezone.utc).isoformat(),
        )

    async def on_broker_client_disconnected(self, *, client_id: str, client_session: Any) -> None:
        log_category(
            LOGGER,
            "MQTT",
            "DISCONNECTED identity=%s ClientId=%s",
            client_session.attributes.get("mqtt_demo.identity", "unknown"),
            client_id,
        )

    async def on_broker_client_subscribed(self, *, client_id: str, topic: str, qos: int) -> None:
        session = self.context.get_session(client_id)
        identity = session.attributes.get("mqtt_demo.identity", "unknown") if session else "unknown"
        log_category(
            LOGGER,
            "MQTT",
            "SUBSCRIBE identity=%s topic=%s Timestamp=%s",
            identity,
            topic,
            datetime.now(timezone.utc).isoformat(),
        )

    async def on_broker_message_broadcast(self, *, client_id: str, message: Any) -> None:
        session = self.context.get_session(client_id)
        if session is None:
            return
        identity = session.attributes.get("mqtt_demo.identity")
        topic = message.topic
        payload = bytes(message.data or b"")
        log_category(
            LOGGER,
            "MQTT",
            "PUBLISH identity=%s topic=%s payload=%s Timestamp=%s",
            identity or "unknown",
            topic,
            payload.decode("utf-8", errors="replace"),
            datetime.now(timezone.utc).isoformat(),
        )
        if not identity:
            return
        pair = topics_for(identity, self.mode)
        if topic != pair.publish:
            return
        log_category(LOGGER, "ECHO", "SCHEDULED identity=%s topic=%s", identity, pair.subscribe)
        task = asyncio.create_task(self._send_echo(identity, pair.subscribe, payload))
        self._echo_tasks.add(task)
        task.add_done_callback(self._echo_task_finished)

    def _echo_task_finished(self, task: asyncio.Task[None]) -> None:
        self._echo_tasks.discard(task)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            log_category(LOGGER, "ERROR", "Echo failed: %s", error)

    async def _send_echo(self, identity: str, topic: str, payload: bytes) -> None:
        await asyncio.sleep(self.echo_delay)
        await self.context.broadcast_message(topic, payload, qos=1)
        log_category(LOGGER, "ECHO", "SENT identity=%s topic=%s", identity, topic)

    async def close(self) -> None:
        for task in tuple(self._echo_tasks):
            task.cancel()
        if self._echo_tasks:
            await asyncio.gather(*self._echo_tasks, return_exceptions=True)
        self._echo_tasks.clear()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("on_"):
            async def ignore_event(**_: Any) -> None:
                return None

            return ignore_event
        raise AttributeError(name)
