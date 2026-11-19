# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for the local mutual-TLS MQTT broker."""

import argparse
import asyncio
from pathlib import Path

from mqtt_demo.broker import BrokerApplication
from mqtt_demo.constants import BROKER_PORT, DEFAULT_ECHO_DELAY_SECONDS, MODES
from mqtt_demo.logging_utils import configure_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the offline mTLS MQTT demonstration broker.")
    parser.add_argument("--mode", choices=MODES, default="generic")
    parser.add_argument(
        "--client-ca",
        type=Path,
        required=True,
        help="PEM client CA certificate/chain file, or folder containing PEM files",
    )
    parser.add_argument("--echo-delay", type=float, default=DEFAULT_ECHO_DELAY_SECONDS)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=BROKER_PORT)
    parser.add_argument("--broker-pki", type=Path, default=Path("broker-pki"))
    return parser.parse_args()


async def _run(application: BrokerApplication) -> None:
    await application.start()
    print(application.startup_information(), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await application.stop()


def main() -> None:
    args = parse_args()
    configure_logging()
    try:
        asyncio.run(
            _run(
                BrokerApplication(
                    client_ca=args.client_ca,
                    mode=args.mode,
                    echo_delay=args.echo_delay,
                    host=args.host,
                    port=args.port,
                    pki_dir=args.broker_pki,
                )
            )
        )
    except KeyboardInterrupt:
        print("\nBroker stopped.", flush=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Broker startup failed: {exc}") from exc


if __name__ == "__main__":
    main()
