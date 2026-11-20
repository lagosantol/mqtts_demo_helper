# mqtts_demo_helper

Offline Mutual-TLS MQTT Broker Demo

Copyright 2026 Avnet, Inc. Licensed under the Apache License, Version 2.0.
See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Authors: Avnet; Laurent Lagosanto <laurent.lagosanto@avnet.eu>.

This project is primarily a local MQTT-over-TLS (MQTTS) demonstration/test broker.
It shows X.509 client-certificate authentication, identity-based authorization,
and topic mappings that resemble Generic MQTT, AWS IoT Core, and Azure IoT Hub.
The optional device simulator under `examples/` is only a convenient test
client; the broker is the main application.

The broker runs on one PC without Docker, cloud services, or a database. After
installing the Python dependencies, all communication and tests are local.

> This is a learning/demo broker, not a production replacement for AWS IoT
> Core, Azure IoT Hub, or an internet-facing MQTT service.

## What the broker demonstrates

- TLS with a broker certificate and required client certificates (mTLS)
- Device identity extracted from the client certificate, not the MQTT username
- Per-identity authorization: publish only to that device's D2C topic and
  subscribe only to its C2D topic
- Generic, AWS-style shadow, and Azure-style topic names
- Delayed echo of accepted D2C messages to the matching C2D topic
- Broker-owned CA and server certificates persisted under `broker-pki/`

Default listener: `0.0.0.0:8883`. Broker PKI is generated on first start and
reused on subsequent starts.

## Project layout

```text
demo_mqtt_broker.py          Broker CLI entry point
mqtt_demo/
  broker.py                  AMQTT broker and lifecycle
  auth.py                    Certificate authentication and topic ACL
  echo.py                    Broker events and delayed echoes
  pki.py                     CA and certificate generation/validation
  topics.py                  Topic mapping and authorization rules
  models.py                  Shared data models
  logging_utils.py           Categorized logging
  constants.py               Defaults
examples/
  device_simulator.py        Optional MQTT test client
tests/                       Local PKI, TLS, authorization, echo, load tests
.vscode/
  launch.json                Broker-first run configurations
pyproject.toml                PyPI package metadata and CLI entry points
LICENSE                       Apache License 2.0
NOTICE                        Avnet and author attribution
```

## Requirements and installation

- Python 3.12 or newer
- A free local TCP port 8883, or select a different port with `--port`

Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

To install the packaged project and its test extras from a local checkout:

```powershell
python -m pip install ".[test]"
```

After publication, install it from PyPI with:

```powershell
python -m pip install mqtts_demo_helper
```

The distribution provides the `demo-mqtt-broker`,
`demo-mqtt-test-client`, and `demo-mqtt-create-device-certificate` commands.

## Publishing to PyPI

The GitHub Actions workflow runs tests on Linux and Windows and builds the
distribution. Publishing a GitHub Release triggers a PyPI upload after the
tests and package checks pass; ordinary pushes and pull requests do not publish.

Before the first release, configure a PyPI Trusted Publisher for
`mqtts_demo_helper` (or a pending publisher if the project does not yet exist):

1. In PyPI's publishing settings, select GitHub as the publisher and enter
   owner `lagosantol`, repository `mqtts_demo_helper`, workflow `workflow.yml`,
   and environment `pypi`.
2. In GitHub, create the `pypi` environment under repository settings and
   configure any desired environment protection rules.
3. Update the version in `pyproject.toml` to a version not already on PyPI,
   push that change, and publish a GitHub Release from that commit.

The workflow uses GitHub's OIDC identity to authenticate with PyPI; no PyPI
API token needs to be stored in the repository. See the
[PyPI Trusted Publishers documentation](https://docs.pypi.org/trusted-publishers/).

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Start the broker, then add a client CA

Start the broker first. It creates the `client-ca/` folder if it does not
already exist. The broker can start with an empty trust folder; client
connections will be accepted only after a trusted client CA is added.

```powershell
python demo_mqtt_broker.py --mode generic --client-ca client-ca
```

The broker generates `broker-pki/broker-ca.crt`, `broker-pki/broker-ca.key`,
`broker-pki/broker.crt`, and `broker-pki/broker.key` if absent. It displays the
public broker CA certificate at startup so clients can verify the broker.
Private keys remain local; do not share them.

Keep this broker terminal running. In a second terminal, generate a local CA
and test-device certificate.
Use the example helper to create/reuse the device certificate and add its CA
to the broker's trust folder:

```powershell
python -m examples.create_device_certificate --identity device001
```

By default, the helper stores device certificates under `device-pki/` and
copies the public CA certificate into `client-ca/device-root-ca.pem`. The
broker rescans that folder for each new TLS connection, so no restart is
needed. It logs and skips files that are not valid PEM certificate(s). The CA
private key remains under `device-pki/` and is used only to issue local
demo/test certificates. Keep it private.

Now start the optional test client from a third terminal:

```powershell
python -m examples.device_simulator --identity device001 --broker localhost --mode generic
```

The client uses its test certificate and trusts `broker-pki/broker-ca.crt`,
subscribes to its C2D topic, and publishes sinusoidal telemetry every five
seconds. The broker echoes accepted messages to the matching C2D topic after
the configured delay.

Use Ctrl+C in the client terminal to stop the client. Use Ctrl+C in the broker
terminal when you are finished with the demo.

### Broker modes and topic access

Select one mode when starting the broker. Every client must use that same mode.

| Mode | Device publishes (D2C) | Device subscribes (C2D) |
|---|---|---|
| `generic` | `device/<identity>/d2c` | `device/<identity>/c2d` |
| `aws` | `$aws/things/<identity>/shadow/update` | `$aws/things/<identity>/shadow/update/delta` |
| `azure` | `devices/<identity>/messages/events/` | `devices/<identity>/messages/devicebound/` |

For example, start AWS-style topic behavior with:

```powershell
python demo_mqtt_broker.py --mode aws --client-ca client-ca
```

An identity may publish only to its own D2C topic and subscribe only to its own
C2D topic. The broker derives the identity from the client X.509 certificate
(URI SAN, DNS SAN, then Common Name). Unauthorized topic access is denied and
logged.

### Broker options

```text
--mode {generic,aws,azure}   Topic convention (default: generic)
--client-ca PATH            PEM CA file/chain, or folder of PEM CA files (required)
--echo-delay SECONDS        Delay before echoing D2C messages (default: 3)
--host HOST                 Bind address (default: 0.0.0.0)
--port PORT                 TLS listener port (default: 8883)
--broker-pki PATH           Broker certificate directory (default: broker-pki)
```

The simulator is only a test client. To test another identity, use the helper
again. It reuses the same device CA, creates the additional device certificate,
and refreshes the CA file in `client-ca/`:

```powershell
python -m examples.create_device_certificate --identity device002
python -m examples.device_simulator --identity device002 --broker localhost --mode generic
```

The device CLI also supports `--port`, `--device-pki`, and `--broker-pki`.

## VS Code

Open **Run and Debug** and start a broker configuration first:

- `MQTT Broker (Generic)` (default)
- `MQTT Broker (AWS-style)`
- `MQTT Broker (Azure-style)`

Start a broker configuration first; it creates the `client-ca/` directory.
Then run `python -m examples.create_device_certificate --identity device001`
in a terminal and start
`MQTT Test Client device001 (Generic)` in a separate debug session. This client
configuration is a test helper and uses Generic topic behavior; for another
mode, change its `--mode` argument in `.vscode/launch.json`.

Create `.venv` and install `requirements.txt` there before using Run and Debug.
Select that `.venv` interpreter in VS Code.

## Tests

The automated tests use temporary PKI directories and localhost. They cover
certificate generation, valid and rejected mTLS clients, per-device topic
authorization, mode-specific echoes, and ten simultaneous test devices.

```powershell
pytest -v
pytest --cov=mqtt_demo -v
```
