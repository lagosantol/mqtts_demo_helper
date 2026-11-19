# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Identity-scoped topic authorization tests."""

import asyncio
import logging

import pytest

from mqtt_demo.models import Mode
from mqtt_demo.topics import is_authorized, topics_for


@pytest.mark.parametrize(
    ("mode", "allowed_publish", "allowed_subscribe", "other_publish", "other_subscribe"),
    [
        ("generic", "device/device001/d2c", "device/device001/c2d", "device/device002/d2c", "device/device002/c2d"),
        (
            "aws",
            "$aws/things/device001/shadow/update",
            "$aws/things/device001/shadow/update/delta",
            "$aws/things/device002/shadow/update",
            "$aws/things/device002/shadow/update/delta",
        ),
        (
            "azure",
            "devices/device001/messages/events/",
            "devices/device001/messages/devicebound/",
            "devices/device002/messages/events/",
            "devices/device002/messages/devicebound/",
        ),
    ],
)
def test_own_topic_access_only(mode, allowed_publish, allowed_subscribe, other_publish, other_subscribe):
    assert is_authorized("device001", allowed_publish, "publish", mode)
    assert is_authorized("device001", allowed_subscribe, "subscribe", mode)
    assert not is_authorized("device001", other_publish, "publish", mode)
    assert not is_authorized("device001", other_subscribe, "subscribe", mode)


def test_unknown_action_and_invalid_identity_are_denied():
    assert not is_authorized("device001", "device/device001/d2c", "receive", Mode.GENERIC)
    with pytest.raises(ValueError):
        topics_for("../device001", Mode.GENERIC)


@pytest.mark.asyncio
async def test_device_cannot_subscribe_to_another_devices_c2d(
    broker_factory,
    mqtt_client_factory,
    caplog,
):
    caplog.set_level(logging.INFO)
    _, port = await broker_factory("generic")
    first, second = await asyncio.gather(
        asyncio.to_thread(mqtt_client_factory, "device001", port),
        asyncio.to_thread(mqtt_client_factory, "device002", port),
    )
    await asyncio.gather(first.wait_connected(), second.wait_connected())
    first.subscribe("device/device002/c2d")
    await asyncio.sleep(0.1)
    second.publish("device/device002/d2c", '{"value":2}')
    with pytest.raises(TimeoutError):
        await first.wait_for_message(timeout=0.3)
    assert any(
        getattr(record, "category", None) == "SECURITY"
        and "DENIED" in record.message
        and "device/device002/c2d" in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_broker_logs_unauthorized_publish(
    broker_factory,
    mqtt_client_factory,
    caplog,
):
    caplog.set_level(logging.DEBUG)
    _, port = await broker_factory("generic")
    client = await asyncio.to_thread(mqtt_client_factory, "device001", port)
    await client.wait_connected()
    client.publish("device/device002/d2c", '{"value":1}')
    await asyncio.sleep(0.1)
    assert any(
        getattr(record, "category", None) == "SECURITY" and "DENIED" in record.message
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_client_ca_directory_is_rescanned_for_each_connection(
    broker_factory,
    mqtt_client_factory,
    temporary_pki,
    caplog,
):
    caplog.set_level(logging.INFO)
    ca_directory = temporary_pki.root / "client-ca"
    ca_directory.mkdir()
    (ca_directory / "device-ca.pem").write_bytes(temporary_pki.client_ca.read_bytes())
    (ca_directory / "not-a-certificate.txt").write_text("not a PEM certificate")
    _, port = await broker_factory("generic", client_ca=ca_directory)
    assert any(
        "Ignoring unreadable client CA file" in record.message
        and "not-a-certificate.txt" in record.message
        for record in caplog.records
    )

    original_client = await asyncio.to_thread(mqtt_client_factory, "device001", port)
    await original_client.wait_connected()

    (ca_directory / "new-device-ca.pem").write_bytes(temporary_pki.rogue_files.ca_certificate.read_bytes())
    added_ca_client = await asyncio.to_thread(
        mqtt_client_factory,
        "rogue001",
        port,
        files=temporary_pki.rogue_files,
    )
    await added_ca_client.wait_connected()
