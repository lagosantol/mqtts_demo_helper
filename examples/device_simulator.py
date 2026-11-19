# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Optional test-client CLI for the local mTLS MQTT broker."""

import argparse
from pathlib import Path

from mqtt_demo.constants import BROKER_PORT, MODES
from mqtt_demo.device import DeviceSimulator
from mqtt_demo.logging_utils import configure_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simulate an mTLS-authenticated MQTT device.")
    parser.add_argument("--identity", required=True)
    parser.add_argument("--broker", required=True, help="Broker DNS name or IP address")
    parser.add_argument("--mode", choices=MODES, default="generic")
    parser.add_argument("--port", type=int, default=BROKER_PORT)
    parser.add_argument("--device-pki", type=Path, default=Path("device-pki"))
    parser.add_argument("--broker-pki", type=Path, default=Path("broker-pki"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    configure_logging()
    device = DeviceSimulator(
        identity=args.identity,
        broker=args.broker,
        mode=args.mode,
        port=args.port,
        pki_dir=args.device_pki,
        broker_pki_dir=args.broker_pki,
    )
    try:
        device.prepare()
        print(device.startup_information(), flush=True)
        device.run()
    except KeyboardInterrupt:
        print("\nDevice stopped.", flush=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Device startup failed: {exc}") from exc
    finally:
        device.stop()


if __name__ == "__main__":
    main()
