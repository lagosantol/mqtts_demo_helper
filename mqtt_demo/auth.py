# Copyright 2026 Avnet, Inc.
# SPDX-License-Identifier: Apache-2.0
"""AMQTT plugins for certificate authentication and topic authorization."""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from amqtt.contexts import Action, BaseContext
from amqtt.plugins.base import BaseAuthPlugin, BaseTopicPlugin
from amqtt.session import Session
from cryptography import x509

from mqtt_demo.logging_utils import log_category
from mqtt_demo.models import Mode
from mqtt_demo.pki import certificate_identity
from mqtt_demo.topics import is_authorized

LOGGER = logging.getLogger(__name__)


class CertificateAuthPlugin(BaseAuthPlugin):
    """Authenticate each MQTT client using the certificate from its TLS session."""

    def __init__(self, context: BaseContext) -> None:
        super().__init__(context)
        self.known_devices: set[str] = set()

    async def authenticate(self, *, session: Session) -> bool:
        ssl_object = session.ssl_object
        if ssl_object is None:
            log_category(LOGGER, "SECURITY", "DENIED missing TLS peer certificate")
            return False
        try:
            der_certificate = ssl_object.getpeercert(binary_form=True)
            if not der_certificate:
                raise ValueError("TLS peer certificate is empty")
            certificate = x509.load_der_x509_certificate(der_certificate)
            identity_info = certificate_identity(certificate)
        except (ValueError, x509.ExtensionNotFound) as exc:
            log_category(LOGGER, "SECURITY", "DENIED invalid client certificate: %s", exc)
            return False

        identity = identity_info.identity
        session.attributes["mqtt_demo.identity"] = identity
        session.attributes["mqtt_demo.certificate"] = identity_info
        session.username = identity
        remote = session.remote_address or "unknown"
        log_category(
            LOGGER,
            "TLS",
            "TLS connection IP=%s Certificate Subject=%s Issuer=%s Serial=%s SHA256=%s",
            remote,
            identity_info.subject,
            identity_info.issuer,
            identity_info.serial_number,
            identity_info.fingerprint_sha256,
        )
        if identity in self.known_devices:
            log_category(LOGGER, "DEVICE", "RECONNECT identity=%s", identity)
        else:
            self.known_devices.add(identity)
            log_category(LOGGER, "DEVICE", "FIRST SEEN identity=%s", identity)
        return True


class DeviceTopicAuthorizationPlugin(BaseTopicPlugin):
    """Enforce exact own-device D2C publish and C2D subscribe topics."""

    @dataclass
    class Config:
        mode: str = "generic"

    def __init__(self, context: BaseContext) -> None:
        super().__init__(context)
        self.mode = Mode(self._get_config_option("mode", "generic"))

    async def topic_filtering(
        self,
        *,
        session: Session | None = None,
        topic: str | None = None,
        action: Action | None = None,
    ) -> bool:
        identity = session.attributes.get("mqtt_demo.identity") if session else None
        action_name = (
            "publish"
            if action == Action.PUBLISH
            else "subscribe"
            if action in (Action.SUBSCRIBE, Action.RECEIVE)
            else ""
        )
        allowed = bool(identity and topic and is_authorized(identity, topic, action_name, self.mode))
        if not allowed:
            log_category(
                LOGGER,
                "SECURITY",
                "DENIED identity=%s action=%s topic=%s timestamp=%s",
                identity or "unknown",
                action_name or str(action),
                topic or "",
                datetime.now(timezone.utc).isoformat(),
            )
        return allowed
