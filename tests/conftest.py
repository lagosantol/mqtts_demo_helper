# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reusable isolated PKI, broker, and MQTT fixtures."""

from __future__ import annotations

import asyncio
import logging
import queue
import socket
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import paho.mqtt.client as mqtt
import pytest
import pytest_asyncio

from mqtt_demo.broker import BrokerApplication
from mqtt_demo.pki import CertificateFiles, ensure_device_certificate


@dataclass(frozen=True)
class TestPKI:
    root: Path
    client_ca: Path
    broker_pki: Path
    device_files: dict[str, CertificateFiles]
    rogue_files: CertificateFiles


@pytest.fixture(scope="session")
def temporary_pki(tmp_path_factory: pytest.TempPathFactory) -> TestPKI:
    """Create test-only device/broker PKI under pytest's temporary directory."""
    root = tmp_path_factory.mktemp("mqtt-test-pki")
    device_pki = root / "device-pki"
    device_files = {
        f"device{index:03d}": ensure_device_certificate(device_pki, f"device{index:03d}")
        for index in range(1, 11)
    }
    rogue_files = ensure_device_certificate(root / "rogue-device-pki", "rogue001")
    broker_pki = root / "broker-pki"
    from mqtt_demo.pki import ensure_broker_pki

    ensure_broker_pki(broker_pki)
    return TestPKI(
        root=root,
        client_ca=device_files["device001"].ca_certificate,
        broker_pki=broker_pki,
        device_files=device_files,
        rogue_files=rogue_files,
    )


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


@pytest_asyncio.fixture
async def broker_factory(temporary_pki: TestPKI):
    """Start an isolated localhost broker for a requested topic mode."""
    applications: list[BrokerApplication] = []

    async def start(
        mode: str = "generic",
        echo_delay: float = 0.1,
        client_ca: Path | None = None,
    ) -> tuple[BrokerApplication, int]:
        port = _free_local_port()
        application = BrokerApplication(
            client_ca=client_ca or temporary_pki.client_ca,
            mode=mode,
            echo_delay=echo_delay,
            host="127.0.0.1",
            port=port,
            pki_dir=temporary_pki.broker_pki,
        )
        await application.start()
        applications.append(application)
        await asyncio.sleep(0.05)
        return application, port

    yield start
    for application in reversed(applications):
        await application.stop()


class MQTTTestClient:
    """Small synchronous Paho client wrapper for integration tests."""

    def __init__(
        self,
        identity: str,
        port: int,
        files: CertificateFiles | None,
        broker_ca: Path,
        client_id: str | None = None,
    ) -> None:
        self.messages: queue.Queue[tuple[str, bytes]] = queue.Queue()
        self.connected = threading.Event()
        self.connect_failure: str | None = None
        self.client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=client_id or identity,
            protocol=mqtt.MQTTv311,
        )
        self.client.enable_logger(logging.getLogger(f"paho.{identity}"))
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(broker_ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if files is not None:
            context.load_cert_chain(str(files.certificate), str(files.key))
        self.client.tls_set_context(context)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.connect("127.0.0.1", port, keepalive=10)
        self.client.loop_start()

    async def wait_connected(self, timeout: float = 5) -> None:
        """Wait without blocking the asyncio loop that runs the broker."""
        connected = await asyncio.to_thread(self.connected.wait, timeout)
        if not connected:
            if self.connect_failure:
                raise ConnectionError(f"MQTT client rejected: {self.connect_failure}")
            raise TimeoutError("MQTT client did not connect")
        if self.connect_failure:
            raise ConnectionError(f"MQTT client rejected: {self.connect_failure}")

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: mqtt.ConnectFlags,
        reason_code: mqtt.ReasonCode,
        properties: mqtt.Properties | None = None,
    ) -> None:
        del client, userdata, flags, properties
        if reason_code.is_failure:
            self.connect_failure = str(reason_code)
        else:
            self.connected.set()

    def _on_message(self, client: mqtt.Client, userdata: Any, message: mqtt.MQTTMessage) -> None:
        del client, userdata
        self.messages.put((message.topic, bytes(message.payload)))

    def subscribe(self, topic: str) -> None:
        result, _ = self.client.subscribe(topic, qos=1)
        if result != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT subscribe failed: {result}")

    def publish(self, topic: str, payload: str | bytes) -> None:
        result = self.client.publish(topic, payload, qos=1)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT publish failed: {result.rc}")

    async def wait_for_message(self, timeout: float = 3) -> tuple[str, bytes]:
        try:
            return await asyncio.to_thread(self.messages.get, True, timeout)
        except queue.Empty as exc:
            raise TimeoutError("No MQTT message received before timeout") from exc

    def close(self) -> None:
        try:
            self.client.disconnect()
        finally:
            self.client.loop_stop()


@pytest.fixture
def mqtt_client_factory(temporary_pki: TestPKI):
    """Create and automatically clean up each localhost MQTT client."""
    clients: list[MQTTTestClient] = []

    def create(
        identity: str,
        port: int,
        files: CertificateFiles | None = None,
        client_id: str | None = None,
    ) -> MQTTTestClient:
        selected_files = files or temporary_pki.device_files[identity]
        client = MQTTTestClient(
            identity,
            port,
            selected_files,
            temporary_pki.broker_pki / "broker-ca.crt",
            client_id=client_id,
        )
        clients.append(client)
        return client

    yield create
    for client in clients:
        client.close()
