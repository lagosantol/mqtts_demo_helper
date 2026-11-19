# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Local X.509 certificate generation and certificate metadata helpers."""

from __future__ import annotations

import ipaddress
import logging
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from mqtt_demo.logging_utils import log_category
from mqtt_demo.models import CertificateIdentity
from mqtt_demo.topics import validate_identity

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CertificateFiles:
    """Paths for a CA and one leaf certificate/key pair."""

    ca_certificate: Path
    ca_key: Path
    certificate: Path
    key: Path


class ClientCAStore:
    """Load PEM certificates from one file or a directory of client CAs."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def scan(self) -> tuple[x509.Certificate, ...]:
        """Read each file, accepting PEM certificates and concatenated chains."""
        if self.path.is_file():
            candidates = [self.path]
        elif self.path.is_dir():
            candidates = sorted(path for path in self.path.iterdir() if path.is_file())
        else:
            raise FileNotFoundError(f"Client CA path does not exist: {self.path}")

        certificates: list[x509.Certificate] = []
        for candidate in candidates:
            try:
                loaded = x509.load_pem_x509_certificates(candidate.read_bytes())
                if not loaded:
                    raise ValueError("file contains no PEM certificates")
                certificates.extend(loaded)
            except (OSError, ValueError) as exc:
                log_category(
                    LOGGER,
                    "ERROR",
                    "Ignoring unreadable client CA file %s: %s",
                    candidate,
                    exc,
                )
        return tuple(certificates)

    def create_server_ssl_context(self, certificate: Path, key: Path) -> ssl.SSLContext:
        """Build a fresh mTLS context using the certificates currently on disk."""
        with self._lock:
            certificates = self.scan()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_cert_chain(str(certificate), str(key))
            if certificates:
                pem_bundle = b"".join(
                    cert.public_bytes(serialization.Encoding.PEM) for cert in certificates
                )
                context.load_verify_locations(cadata=pem_bundle.decode("ascii"))
            return context

    def subjects(self) -> tuple[str, ...]:
        """Return the subjects of the certificates currently loaded from disk."""
        return tuple(certificate.subject.rfc4514_string() for certificate in self.scan())


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    try:
        path.chmod(0o600)
    except OSError:
        LOGGER.debug("Could not restrict permissions for %s", path)


def _new_rsa_key(bits: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _validate_key_pair(certificate: x509.Certificate, key: rsa.RSAPrivateKey, path: Path) -> None:
    certificate_key = certificate.public_key()
    if not isinstance(certificate_key, rsa.RSAPublicKey):
        raise ValueError(f"Certificate at {path} does not contain an RSA public key")
    if certificate_key.public_numbers() != key.public_key().public_numbers():
        raise ValueError(f"Private key does not match certificate at {path}")


def _create_ca(directory: Path, common_name: str) -> tuple[Path, Path, x509.Certificate, rsa.RSAPrivateKey]:
    directory.mkdir(parents=True, exist_ok=True)
    certificate_path = directory / f"{'broker' if 'Broker' in common_name else 'device'}-ca.crt"
    key_path = directory / f"{'broker' if 'Broker' in common_name else 'device'}-ca.key"
    if certificate_path.exists() and key_path.exists():
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"CA key at {key_path} is not RSA")
        _validate_key_pair(certificate, key, certificate_path)
        if certificate.subject != _name(common_name) or certificate.issuer != certificate.subject:
            raise ValueError(f"CA certificate at {certificate_path} has an unexpected subject or issuer")
        try:
            if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError(f"CA certificate at {certificate_path} is not a CA")
        except x509.ExtensionNotFound as exc:
            raise ValueError(f"CA certificate at {certificate_path} has no CA constraints") from exc
        return certificate_path, key_path, certificate, key
    if certificate_path.exists() != key_path.exists():
        raise FileNotFoundError(f"Incomplete CA files in {directory}; remove or restore both CA files")

    key = _new_rsa_key(4096)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _write_private_key(key_path, key)
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate_path, key_path, certificate, key


def _create_leaf(
    certificate_path: Path,
    key_path: Path,
    identity: str,
    ca_certificate: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    server: bool,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    if certificate_path.exists() and key_path.exists():
        certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError(f"Certificate key at {key_path} is not RSA")
        _validate_key_pair(certificate, key, certificate_path)
        if certificate.subject != _name(identity) or certificate.issuer != ca_certificate.subject:
            raise ValueError(f"Certificate at {certificate_path} has an unexpected subject or issuer")
        return certificate, key
    if certificate_path.exists() != key_path.exists():
        raise FileNotFoundError(f"Incomplete certificate/key pair: {certificate_path} and {key_path}")

    key = _new_rsa_key(2048)
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(identity))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_certificate.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if server else x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
    certificate = builder.sign(ca_key, hashes.SHA256())
    _write_private_key(key_path, key)
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return certificate, key


def ensure_broker_pki(directory: Path) -> CertificateFiles:
    """Create or reuse the broker CA and localhost server certificate."""
    ca_cert_path, ca_key_path, ca_certificate, ca_key = _create_ca(directory, "Demo MQTT Broker Root CA")
    cert_path = directory / "broker.crt"
    key_path = directory / "broker.key"
    _create_leaf(cert_path, key_path, "localhost", ca_certificate, ca_key, server=True)
    return CertificateFiles(ca_cert_path, ca_key_path, cert_path, key_path)


def ensure_device_certificate(directory: Path, identity: str) -> CertificateFiles:
    """Create or reuse the device CA and the requested device certificate."""
    validate_identity(identity)
    ca_cert_path, ca_key_path, ca_certificate, ca_key = _create_ca(directory, "Demo MQTT Device Root CA")
    cert_path = directory / f"{identity}.crt"
    key_path = directory / f"{identity}.key"
    _create_leaf(cert_path, key_path, identity, ca_certificate, ca_key, server=False)
    return CertificateFiles(ca_cert_path, ca_key_path, cert_path, key_path)


def load_certificate(path: Path) -> x509.Certificate:
    """Load a PEM X.509 certificate."""
    return x509.load_pem_x509_certificate(path.read_bytes())


def certificate_subject(certificate: x509.Certificate) -> str:
    """Return a readable RFC4514 subject name."""
    return certificate.subject.rfc4514_string()


def extract_identity(certificate: x509.Certificate) -> str:
    """Extract identity from URI SAN, DNS SAN, then Common Name."""
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        if uris:
            uri = uris[0]
            parsed_uri = urlsplit(uri)
            identity = parsed_uri.path.rstrip("/").rsplit("/", 1)[-1] if parsed_uri.path else uri.rsplit(":", 1)[-1]
            return validate_identity(identity)
        dns_names = san.get_values_for_type(x509.DNSName)
        if dns_names:
            return validate_identity(dns_names[0])
    except x509.ExtensionNotFound:
        pass
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_names:
        raise ValueError("Client certificate has no URI/DNS SAN or Common Name identity")
    return validate_identity(common_names[0].value)


def certificate_identity(certificate: x509.Certificate) -> CertificateIdentity:
    """Collect identity and logging fields from a certificate."""
    return CertificateIdentity(
        identity=extract_identity(certificate),
        subject=certificate_subject(certificate),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=format(certificate.serial_number, "x"),
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
    )


def verify_certificate_chain(certificate_path: Path, ca_path: Path) -> bool:
    """Validate a leaf certificate signature and validity against a single CA."""
    certificate = load_certificate(certificate_path)
    ca = load_certificate(ca_path)
    if certificate.issuer != ca.subject:
        return False
    now = datetime.now(timezone.utc)
    if certificate.not_valid_before_utc > now or certificate.not_valid_after_utc < now:
        return False
    try:
        ca.public_key().verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except (ValueError, TypeError):
        return False
    return True


def create_client_ssl_context(files: CertificateFiles, broker_ca: Path) -> ssl.SSLContext:
    """Create a TLS client context trusting the broker CA and presenting device credentials."""
    if not broker_ca.is_file():
        raise FileNotFoundError(f"Broker CA certificate not found: {broker_ca}")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(broker_ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(files.certificate), str(files.key))
    return context
