# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Mutual-TLS admission and client-certificate rejection tests."""

import asyncio
import ssl

import paho.mqtt.client as mqtt
import pytest


@pytest.mark.asyncio
async def test_valid_certificate_connects(broker_factory, mqtt_client_factory):
    _, port = await broker_factory("generic")
    client = await asyncio.to_thread(mqtt_client_factory, "device001", port)
    await client.wait_connected()
    assert client.connected.is_set()


@pytest.mark.asyncio
async def test_broker_creates_missing_client_ca_folder(broker_factory, temporary_pki):
    client_ca = temporary_pki.root / "created-client-ca"
    assert not client_ca.exists()
    _, _ = await broker_factory("generic", client_ca=client_ca)
    assert client_ca.is_dir()


@pytest.mark.asyncio
async def test_rogue_ca_certificate_is_rejected(
    broker_factory,
    mqtt_client_factory,
    temporary_pki,
    caplog,
):
    import logging

    caplog.set_level(logging.INFO)
    _, port = await broker_factory("generic")
    try:
        client = await asyncio.to_thread(
            mqtt_client_factory,
            "rogue001",
            port,
            files=temporary_pki.rogue_files,
        )
    except (ssl.SSLError, OSError, TimeoutError, ConnectionError):
        return
    try:
        with pytest.raises((TimeoutError, ConnectionError)):
            await client.wait_connected(timeout=1)
    finally:
        client.close()
    assert not any("rogue001" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_missing_client_certificate_is_rejected(
    broker_factory,
    temporary_pki,
):
    _, port = await broker_factory("generic")
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(temporary_pki.broker_pki / "broker-ca.crt"),
    )
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="missing-cert")
    client.tls_set_context(context)
    accepted = asyncio.Event()

    def on_connect(
        mqtt_client,
        userdata,
        flags,
        reason_code,
        properties=None,
    ):
        del mqtt_client, userdata, flags, properties
        if not reason_code.is_failure:
            accepted.set()

    client.on_connect = on_connect
    try:
        await asyncio.to_thread(client.connect, "127.0.0.1", port, 5)
        client.loop_start()
        await asyncio.sleep(0.5)
        assert not accepted.is_set()
    finally:
        client.disconnect()
        client.loop_stop()


def test_wrong_private_key_is_rejected(temporary_pki):
    valid = temporary_pki.device_files["device001"]
    wrong = temporary_pki.device_files["device002"]
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=str(temporary_pki.broker_pki / "broker-ca.crt"),
    )
    with pytest.raises(ssl.SSLError):
        context.load_cert_chain(str(valid.certificate), str(wrong.key))
