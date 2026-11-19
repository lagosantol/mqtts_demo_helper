# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared configuration defaults for the MQTT demonstration."""

from pathlib import Path

BROKER_HOST = "0.0.0.0"
BROKER_PORT = 8883
BROKER_PKI_DIR = Path("broker-pki")
DEVICE_PKI_DIR = Path("device-pki")
TELEMETRY_INTERVAL_SECONDS = 5.0
TELEMETRY_PERIOD_SECONDS = 60.0
DEFAULT_ECHO_DELAY_SECONDS = 3.0
MODES = ("generic", "aws", "azure")
