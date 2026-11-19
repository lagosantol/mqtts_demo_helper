# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Topic construction and exact authorization rules."""

import re

from mqtt_demo.models import Mode, TopicPair

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def validate_identity(identity: str) -> str:
    """Validate identities before using them in certificate subjects or topics."""
    if not _IDENTITY_RE.fullmatch(identity):
        raise ValueError("Identity must be 1-128 characters: letters, digits, dot, underscore, hyphen")
    return identity


def topics_for(identity: str, mode: Mode | str) -> TopicPair:
    """Return exact D2C and C2D topic names for a device and mode."""
    validate_identity(identity)
    selected = Mode(mode)
    if selected is Mode.AWS:
        return TopicPair(
            publish=f"$aws/things/{identity}/shadow/update",
            subscribe=f"$aws/things/{identity}/shadow/update/delta",
        )
    if selected is Mode.AZURE:
        return TopicPair(
            publish=f"devices/{identity}/messages/events/",
            subscribe=f"devices/{identity}/messages/devicebound/",
        )
    return TopicPair(publish=f"device/{identity}/d2c", subscribe=f"device/{identity}/c2d")


def is_authorized(identity: str, topic: str, action: str, mode: Mode | str) -> bool:
    """Allow a device only its exact mode-specific publish or subscription topic."""
    pair = topics_for(identity, mode)
    if action == "publish":
        return topic == pair.publish
    if action == "subscribe":
        return topic == pair.subscribe
    return False
