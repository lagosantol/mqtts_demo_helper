# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reusable local mTLS MQTT broker application."""

from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path
from typing import Any

from amqtt.broker import Broker
from amqtt.contexts import Action, ListenerConfig, ListenerType
from amqtt.events import BrokerEvents
from amqtt.mqtt.protocol.broker_handler import BrokerProtocolHandler
from amqtt.session import Session

from mqtt_demo.constants import BROKER_HOST, BROKER_PORT, BROKER_PKI_DIR, DEFAULT_ECHO_DELAY_SECONDS
from mqtt_demo.logging_utils import log_category
from mqtt_demo.models import Mode
from mqtt_demo.pki import (
    CertificateFiles,
    ClientCAStore,
    certificate_subject,
    ensure_broker_pki,
    load_certificate,
)

LOGGER = logging.getLogger(__name__)


class DemoBroker(Broker):
    """AMQTT broker with AWS shadow topic compatibility and delayed echoes."""

    def __init__(self, config: dict[str, Any], client_ca_store: ClientCAStore) -> None:
        self.client_ca_store = client_ca_store
        super().__init__(config)

    def _create_ssl_context(self, listener: ListenerConfig) -> ssl.SSLContext:
        """Create a required-client-certificate context from the current CA store."""
        return self.client_ca_store.create_server_ssl_context(listener["certfile"], listener["keyfile"])

    async def _create_server_instance(
        self,
        listener_name: str,
        listener_type: ListenerType,
        address: str | None,
        port: int,
        ssl_context: ssl.SSLContext | None,
    ) -> asyncio.Server:
        """Refresh client trust before each TLS handshake, including without SNI."""
        if listener_type is not ListenerType.TCP or ssl_context is None:
            result = await super()._create_server_instance(
                listener_name,
                listener_type,
                address,
                port,
                ssl_context,
            )
            if not isinstance(result, asyncio.Server):
                raise TypeError("The MQTT demo broker supports TCP listeners only")
            return result

        listener = self.listeners_config[listener_name]

        async def accept_tls_client(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
        ) -> None:
            peer = writer.get_extra_info("peername")
            ip_address = peer[0] if isinstance(peer, tuple) and peer else "unknown"
            try:
                context = self.client_ca_store.create_server_ssl_context(
                    listener["certfile"],
                    listener["keyfile"],
                )
                loop = asyncio.get_running_loop()
                transport = await loop.start_tls(
                    writer.transport,
                    writer._protocol,
                    context,
                    server_side=True,
                    ssl_handshake_timeout=10,
                )
                if transport is None:
                    raise ssl.SSLError("TLS transport setup failed")
                writer._transport = transport
            except (OSError, ssl.SSLError, TimeoutError) as exc:
                log_category(
                    LOGGER,
                    "SECURITY",
                    "DENIED TLS connection IP=%s reason=%s",
                    ip_address,
                    exc,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    LOGGER.debug("Socket already closed after rejected TLS connection from %s", ip_address)
                return

            await self.stream_connected(reader, writer, listener_name)

        return await asyncio.start_server(
            accept_tls_client,
            address,
            port,
            reuse_address=True,
        )

    async def _handle_message_delivery(
        self,
        client_session: Session,
        handler: BrokerProtocolHandler,
        wait_deliver: asyncio.Future[Any],
    ) -> bool:
        """Accept '$aws' topics, which AMQTT's standard path rejects unconditionally."""
        app_message = wait_deliver.result()
        await self.plugins_manager.fire_event(
            BrokerEvents.MESSAGE_RECEIVED,
            client_id=client_session.client_id,
            message=app_message,
        )
        if app_message is None:
            return True
        topic = app_message.topic
        if (
            not topic
            or "#" in topic
            or "+" in topic
            or (topic.startswith("$") and not topic.startswith("$aws/"))
        ):
            log_category(LOGGER, "SECURITY", "DENIED invalid publish topic=%s", topic or "")
            return False
        permitted = await self._topic_filtering(client_session, topic=topic, action=Action.PUBLISH)
        if not permitted:
            log_category(
                LOGGER,
                "SECURITY",
                "DENIED identity=%s action=publish topic=%s",
                client_session.attributes.get("mqtt_demo.identity", "unknown"),
                topic,
            )
        else:
            await self.plugins_manager.fire_event(
                BrokerEvents.MESSAGE_BROADCAST,
                client_id=client_session.client_id,
                message=app_message,
            )
            await self._broadcast_message(client_session, topic, app_message.data)
            if app_message.publish_packet and app_message.publish_packet.retain_flag:
                await self.retain_message(client_session, topic, app_message.data, app_message.qos)
        return True


class BrokerApplication:
    """Owns PKI setup and lifecycle for an AMQTT broker instance."""

    def __init__(
        self,
        client_ca: Path,
        mode: Mode | str = Mode.GENERIC,
        echo_delay: float = DEFAULT_ECHO_DELAY_SECONDS,
        host: str = BROKER_HOST,
        port: int = BROKER_PORT,
        pki_dir: Path = BROKER_PKI_DIR,
    ) -> None:
        if echo_delay < 0:
            raise ValueError("Echo delay must be zero or greater")
        self.client_ca = client_ca
        self.mode = Mode(mode)
        self.echo_delay = echo_delay
        self.host = host
        self.port = port
        self.pki_dir = pki_dir
        self.certificate_files: CertificateFiles | None = None
        self.broker: DemoBroker | None = None

    def prepare(self) -> None:
        """Generate/reuse broker identity and validate the supplied client CA path."""
        if not self.client_ca.exists():
            self.client_ca.mkdir(parents=True, exist_ok=True)
        ClientCAStore(self.client_ca).scan()
        self.certificate_files = ensure_broker_pki(self.pki_dir)

    def startup_information(self) -> str:
        """Return operator-facing broker configuration and broker CA PEM."""
        if self.certificate_files is None:
            raise RuntimeError("Broker PKI has not been prepared")
        broker_ca = load_certificate(self.certificate_files.ca_certificate)
        broker_certificate = load_certificate(self.certificate_files.certificate)
        client_ca_subjects = ClientCAStore(self.client_ca).subjects()
        ca_pem = self.certificate_files.ca_certificate.read_text(encoding="ascii")
        client_ca_display = "\n".join(client_ca_subjects) or "No valid client CA certificates currently loaded"
        return (
            "==================================================\n"
            "Demo MQTT Broker\n"
            "==================================================\n\n"
            f"Mode: {self.mode.value}\n"
            f"Port: {self.port}\n"
            f"Echo Delay: {self.echo_delay:g} seconds\n\n"
            f"Broker CA Subject: {certificate_subject(broker_ca)}\n"
            f"Broker Certificate Subject: {certificate_subject(broker_certificate)}\n"
            f"Client CA Subject(s):\n{client_ca_display}\n\n"
            "Mutual TLS Enabled: Yes\n\n"
            "Broker CA PEM (copy this certificate to clients):\n"
            f"{ca_pem}"
        )

    async def start(self) -> None:
        """Start listening on the configured TLS port."""
        self.prepare()
        assert self.certificate_files is not None
        config: dict[str, Any] = {
            "listeners": {
                "default": {
                    "type": "tcp",
                    "bind": f"{self.host}:{self.port}",
                    "ssl": True,
                    "certfile": str(self.certificate_files.certificate),
                    "keyfile": str(self.certificate_files.key),
                }
            },
            "plugins": {
                "mqtt_demo.auth.CertificateAuthPlugin": {},
                "mqtt_demo.auth.DeviceTopicAuthorizationPlugin": {"mode": self.mode.value},
                "mqtt_demo.echo.BrokerEventPlugin": {
                    "mode": self.mode.value,
                    "echo_delay": self.echo_delay,
                },
            },
        }
        self.broker = DemoBroker(config, ClientCAStore(self.client_ca))
        await self.broker.start()
        log_category(LOGGER, "INFO", "Broker listening on %s:%s", self.host, self.port)

    async def stop(self) -> None:
        """Gracefully shut down the broker and pending echo tasks."""
        if self.broker is not None:
            await self.broker.shutdown()
            self.broker = None

    async def serve_forever(self) -> None:
        """Run until cancelled by the CLI or its caller."""
        if self.broker is None:
            await self.start()
        try:
            await asyncio.Event().wait()
        finally:
            await self.stop()
