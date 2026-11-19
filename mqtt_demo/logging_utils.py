# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Consistent console logging for the command-line applications."""

import logging
import sys

from colorama import Fore, Style, init


class CategoryFormatter(logging.Formatter):
    """Format records with a stable category prefix."""

    COLORS = {
        "INFO": Fore.GREEN,
        "TLS": Fore.CYAN,
        "MQTT": Fore.BLUE,
        "DEVICE": Fore.MAGENTA,
        "SECURITY": Fore.YELLOW,
        "ECHO": Fore.GREEN,
        "ERROR": Fore.RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        category = getattr(record, "category", record.levelname)
        color = self.COLORS.get(category, "")
        return f"{color}[{category}] {super().format(record)}{Style.RESET_ALL}"


def configure_logging(level: int = logging.INFO) -> None:
    """Initialize root logging once for terminal-friendly output."""
    init(autoreset=True)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CategoryFormatter("%(asctime)s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


def log_category(logger: logging.Logger, category: str, message: str, *args: object) -> None:
    """Emit a message with an explicit application category."""
    level = logging.ERROR if category == "ERROR" else logging.INFO
    logger.log(level, message, *args, extra={"category": category})
