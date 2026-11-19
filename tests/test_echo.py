# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""End-to-end delayed echo tests for every supported topic convention."""

import asyncio

import pytest

from mqtt_demo.topics import topics_for


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["generic", "aws", "azure"])
async def test_matching_d2c_message_is_echoed_to_own_c2d(
    mode,
    broker_factory,
    mqtt_client_factory,
    caplog,
):
    import logging

    caplog.set_level(logging.DEBUG)
    _, port = await broker_factory(mode, echo_delay=0.1)
    client = await asyncio.to_thread(mqtt_client_factory, "device001", port)
    await client.wait_connected()
    pair = topics_for("device001", mode)
    client.subscribe(pair.subscribe)
    await asyncio.sleep(0.1)
    payload = '{"value":123}'
    client.publish(pair.publish, payload)
    await asyncio.sleep(0.3)
    assert any("SCHEDULED" in record.message for record in caplog.records)
    assert any("SENT" in record.message for record in caplog.records)
    for expected in ("TLS connection", "FIRST SEEN", "CONNECTED", "SUBSCRIBE", "PUBLISH"):
        assert any(expected in record.message for record in caplog.records)
    topic, received = await client.wait_for_message(timeout=4)
    assert topic == pair.subscribe
    assert received.decode() == payload


@pytest.mark.asyncio
async def test_echo_is_isolated_between_devices(
    broker_factory,
    mqtt_client_factory,
):
    _, port = await broker_factory("generic", echo_delay=0.1)
    first, second = await asyncio.gather(
        asyncio.to_thread(mqtt_client_factory, "device001", port),
        asyncio.to_thread(mqtt_client_factory, "device002", port),
    )
    await first.wait_connected()
    await second.wait_connected()
    first.subscribe(topics_for("device001", "generic").subscribe)
    second.subscribe(topics_for("device002", "generic").subscribe)
    await asyncio.sleep(0.1)
    first.publish(topics_for("device001", "generic").publish, '{"device":1}')
    topic, payload = await first.wait_for_message(timeout=4)
    assert topic == "device/device001/c2d"
    assert payload == b'{"device":1}'
    with pytest.raises(TimeoutError):
        await second.wait_for_message(timeout=0.3)
