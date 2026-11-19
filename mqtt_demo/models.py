# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Small typed models shared across application modules."""

from dataclasses import dataclass
from enum import Enum


class Mode(str, Enum):
    """Supported MQTT topic conventions."""

    GENERIC = "generic"
    AWS = "aws"
    AZURE = "azure"


@dataclass(frozen=True)
class TopicPair:
    """The device-to-cloud and cloud-to-device topics for one identity."""

    publish: str
    subscribe: str


@dataclass(frozen=True)
class CertificateIdentity:
    """Identity and metadata extracted from an X.509 certificate."""

    identity: str
    subject: str
    issuer: str
    serial_number: str
    fingerprint_sha256: str
