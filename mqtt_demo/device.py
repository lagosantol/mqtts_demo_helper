# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reusable MQTT device simulator with automatic mTLS reconnection."""

from __future__ import annotations

import json
import logging
import math
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paho.mqtt.client as mqtt

from mqtt_demo.constants import DEVICE_PKI_DIR, TELEMETRY_INTERVAL_SECONDS, TELEMETRY_PERIOD_SECONDS
from mqtt_demo.logging_utils import log_category
from mqtt_demo.models import Mode
from mqtt_demo.pki import CertificateFiles, certificate_subject, create_client_ssl_context, ensure_device_certificate, load_certificate
from mqtt_demo.topics import topics_for, validate_identity

LOGGER = logging.getLogger(__name__)


class DeviceSimulator:
    """Connect, subscribe, publish periodic telemetry, and reconnect as needed."""

    def __init__(
        self,
        identity: str,
        broker: str,
        mode: Mode | str = Mode.GENERIC,
        port: int = 8883,
        pki_dir: Path = DEVICE_PKI_DIR,
        broker_pki_dir: Path = Path("broker-pki"),
        telemetry_interval: float = TELEMETRY_INTERVAL_SECONDS,
        telemetry_period: float = TELEMETRY_PERIOD_SECONDS,
    ) -> None:
        self.identity = validate_identity(identity)
        self.broker = broker
        self.mode = Mode(mode)
        self.port = port
        self.pki_dir = pki_dir
        self.broker_ca = broker_pki_dir / "broker-ca.crt"
        self.telemetry_interval = telemetry_interval
        self.telemetry_period = telemetry_period
        if self.telemetry_interval <= 0 or self.telemetry_period <= 0:
            raise ValueError("Telemetry interval and period must be greater than zero")
        self.files: CertificateFiles | None = None
        self.client: mqtt.Client | None = None
        self._connected = threading.Event()
        self._stop = threading.Event()
        self._started_at = time.monotonic()
        self._ever_connected = False

    def prepare(self) -> None:
        """Create or reuse local device credentials and require broker CA trust."""
        self.files = ensure_device_certificate(self.pki_dir, self.identity)
        if not self.broker_ca.is_file():
            raise FileNotFoundError(
                f"Broker CA certificate not found: {self.broker_ca}. "
                "Start the broker once and copy its broker-ca.crt into broker-pki."
            )

    def startup_information(self) -> str:
        """Return connection target and local certificate identity details."""
        if self.files is None:
            raise RuntimeError("Device PKI has not been prepared")
        certificate = load_certificate(self.files.certificate)
        return (
            f"Identity: {self.identity}\n"
            f"Mode: {self.mode.value}\n"
            f"Broker Hostname: {self.broker}\n"
            f"Broker Port: {self.port}\n\n"
            f"Certificate Subject: {certificate_subject(certificate)}\n"
            f"Certificate Issuer: {certificate.issuer.rfc4514_string()}"
        )

    def _on_connect(
        self,
        client: mqtt.Client,
        userdata: Any,
        flags: mqtt.ConnectFlags,
        reason_code: mqtt.ReasonCode,
        properties: mqtt.Properties | None = None,
    ) -> None:
        del userdata, flags, properties
        if reason_code.is_failure:
            log_category(LOGGER, "ERROR", "MQTT connection rejected: %s", reason_code)
            return
        self._connected.set()
        category = "RECONNECTED" if self._ever_connected else "CONNECTED"
        log_category(LOGGER, "MQTT", "%s identity=%s", category, self.identity)
        self._ever_connected = True
        client.subscribe(topics_for(self.identity, self.mode).subscribe, qos=1)

    def _on_disconnect(
        self,
        client: mqtt.Client,
        userdata: Any,
        disconnect_flags: mqtt.DisconnectFlags,
        reason_code: mqtt.ReasonCode,
        properties: mqtt.Properties | None = None,
    ) -> None:
        del client, userdata, disconnect_flags, properties
        self._connected.clear()
        if not self._stop.is_set():
            log_category(LOGGER, "MQTT", "DISCONNECTED identity=%s reason=%s", self.identity, reason_code)

    def _on_message(self, client: mqtt.Client, userdata: Any, message: mqtt.MQTTMessage) -> None:
        del client, userdata
        log_category(
            LOGGER,
            "MQTT",
            "[C2D] Topic=%s Payload=%s",
            message.topic,
            message.payload.decode("utf-8", errors="replace"),
        )

    def _make_client(self) -> mqtt.Client:
        self.prepare()
        assert self.files is not None
        client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id=self.identity,
            protocol=mqtt.MQTTv311,
            reconnect_on_failure=True,
        )
        client.tls_set_context(create_client_ssl_context(self.files, self.broker_ca))
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message
        client.reconnect_delay_set(min_delay=1, max_delay=30)
        return client

    def telemetry_payload(self, elapsed_seconds: float) -> str:
        """Build the simulator's sinusoidal UTC telemetry JSON."""
        value = math.sin(2 * math.pi * elapsed_seconds / self.telemetry_period)
        return json.dumps(
            {
                "deviceId": self.identity,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "value": round(value, 3),
            },
            separators=(",", ":"),
        )

    def publish_once(self, elapsed_seconds: float | None = None) -> str:
        """Publish one telemetry message (useful to callers and tests)."""
        if self.client is None or not self._connected.is_set():
            raise RuntimeError("Device is not connected")
        elapsed = time.monotonic() - self._started_at if elapsed_seconds is None else elapsed_seconds
        payload = self.telemetry_payload(elapsed)
        topic = topics_for(self.identity, self.mode).publish
        result = self.client.publish(topic, payload, qos=1)
        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError(f"MQTT publish failed with result code {result.rc}")
        log_category(LOGGER, "MQTT", "[D2C] Topic=%s Payload=%s", topic, payload)
        return payload

    def run(self) -> None:
        """Connect and keep publishing until stop() or Ctrl+C."""
        self.client = self._make_client()
        self.client.connect_async(self.broker, self.port, keepalive=60)
        self.client.loop_start()
        self._started_at = time.monotonic()
        try:
            while not self._stop.is_set():
                if self._connected.wait(timeout=0.25):
                    if self._stop.wait(self.telemetry_interval):
                        break
                    if self._connected.is_set():
                        self.publish_once()
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop telemetry and the Paho network loop."""
        self._stop.set()
        if self.client is not None:
            self.client.disconnect()
            self.client.loop_stop()
            self.client = None
