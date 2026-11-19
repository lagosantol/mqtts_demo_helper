# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Local multi-device connection and echo load test."""

import asyncio
import logging

import pytest

from mqtt_demo.topics import topics_for


@pytest.mark.asyncio
async def test_ten_devices_publish_five_messages_and_receive_echoes(
    broker_factory,
    mqtt_client_factory,
    caplog,
):
    caplog.set_level(logging.ERROR)
    _, port = await broker_factory("generic", echo_delay=0.02)
    clients = await asyncio.gather(
        *(
            asyncio.to_thread(mqtt_client_factory, f"device{index:03d}", port)
            for index in range(1, 11)
        )
    )
    await asyncio.gather(*(client.wait_connected() for client in clients))
    for index, client in enumerate(clients, 1):
        client.subscribe(topics_for(f"device{index:03d}", "generic").subscribe)
    await asyncio.sleep(0.2)

    for index, client in enumerate(clients, 1):
        topic = topics_for(f"device{index:03d}", "generic").publish
        for message_number in range(5):
            client.publish(topic, f'{{"device":{index},"message":{message_number}}}')

    for index, client in enumerate(clients, 1):
        expected_topic = topics_for(f"device{index:03d}", "generic").subscribe
        received = [await client.wait_for_message(timeout=8) for _ in range(5)]
        assert all(topic == expected_topic for topic, _ in received)
        assert len({payload for _, payload in received}) == 5
    assert not any(
        "Task exception was never retrieved" in record.message or "Echo failed" in record.message
        for record in caplog.records
    )
