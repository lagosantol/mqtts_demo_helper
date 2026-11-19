# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Certificate generation and chain validation tests."""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from examples.create_device_certificate import create_device_credentials
from mqtt_demo.pki import (
    ensure_broker_pki,
    ensure_device_certificate,
    extract_identity,
    verify_certificate_chain,
)


def test_broker_pki_creation_and_persistence(tmp_path):
    files = ensure_broker_pki(tmp_path / "broker-pki")
    assert {path.name for path in files.ca_certificate.parent.iterdir()} == {
        "broker-ca.crt",
        "broker-ca.key",
        "broker.crt",
        "broker.key",
    }
    ca = x509.load_pem_x509_certificate(files.ca_certificate.read_bytes())
    broker = x509.load_pem_x509_certificate(files.certificate.read_bytes())
    assert ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Demo MQTT Broker Root CA"
    assert broker.issuer == ca.subject
    assert ensure_broker_pki(files.ca_certificate.parent) == files


def test_device_pki_identity_and_chain(tmp_path):
    files = ensure_device_certificate(tmp_path / "device-pki", "device001")
    assert {path.name for path in files.ca_certificate.parent.iterdir()} == {
        "device-ca.crt",
        "device-ca.key",
        "device001.crt",
        "device001.key",
    }
    device = x509.load_pem_x509_certificate(files.certificate.read_bytes())
    ca = x509.load_pem_x509_certificate(files.ca_certificate.read_bytes())
    assert device.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "device001"
    assert verify_certificate_chain(files.certificate, files.ca_certificate)
    ca.public_key().verify(
        device.signature,
        device.tbs_certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    assert extract_identity(device) == "device001"


def test_example_helper_adds_device_ca_to_broker_trust_folder(tmp_path):
    device_pki = tmp_path / "device-pki"
    client_ca = tmp_path / "client-ca"

    files = create_device_credentials("device001", device_pki, client_ca)

    assert (client_ca / "device-root-ca.pem").read_bytes() == files.ca_certificate.read_bytes()
    assert (device_pki / "device001.crt").is_file()
    assert (device_pki / "device001.key").is_file()
