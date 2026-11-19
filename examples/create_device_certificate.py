# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create a test-device certificate and add its CA to the broker trust folder."""

import argparse
import logging
from pathlib import Path

from mqtt_demo.constants import DEVICE_PKI_DIR
from mqtt_demo.logging_utils import configure_logging, log_category
from mqtt_demo.pki import CertificateFiles, ensure_device_certificate
from mqtt_demo.topics import validate_identity

LOGGER = logging.getLogger(__name__)
DEFAULT_CLIENT_CA_DIR = Path("client-ca")


def create_device_credentials(
    identity: str,
    device_pki_dir: Path = DEVICE_PKI_DIR,
    client_ca_dir: Path = DEFAULT_CLIENT_CA_DIR,
) -> CertificateFiles:
    """Create/reuse one device certificate and install its public CA for the broker."""
    validate_identity(identity)
    files = ensure_device_certificate(device_pki_dir, identity)
    client_ca_dir.mkdir(parents=True, exist_ok=True)
    trusted_ca_path = client_ca_dir / "device-root-ca.pem"
    trusted_ca_path.write_bytes(files.ca_certificate.read_bytes())
    log_category(
        LOGGER,
        "INFO",
        "Created/reused certificate for %s: %s; added client CA: %s",
        identity,
        files.certificate,
        trusted_ca_path,
    )
    return files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create an MQTT demo device certificate and trust its CA in the broker."
    )
    parser.add_argument("--identity", required=True, help="Device identity, for example device001")
    parser.add_argument("--device-pki", type=Path, default=DEVICE_PKI_DIR)
    parser.add_argument("--client-ca", type=Path, default=DEFAULT_CLIENT_CA_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging()
    try:
        create_device_credentials(args.identity, args.device_pki, args.client_ca)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Device certificate setup failed: {exc}") from exc


if __name__ == "__main__":
    main()
