# PiSAT

PiSAT is a C++20/CMake service for **passive, authorized** Wi-Fi observation on a
Raspberry Pi with an Alfa AWUS036ACH (Realtek RTL8812AU) adapter. It controls
monitor mode, runs established capture tools, continuously ingests
`airodump-ng` survey data, and exposes current devices and capture controls over
an SX126x LoRa HAT. An HTTP diagnostics API can be enabled separately.

PiSAT does not implement packet injection, deauthentication, credential
recovery, or traffic modification. Use it only on networks and radio spectrum
you are authorized to monitor.

## Raspberry Pi setup

Use Raspberry Pi OS 64-bit and verify that the adapter's driver supports
monitor mode:

```bash
ip link
iw list | sed -n '/Supported interface modes:/,/Band/p'
```

The adapter is usually `wlan1`; update `config/pisat.conf` if it differs. Some
Raspberry Pi OS/kernel combinations require an out-of-tree RTL8812AU driver.
Choose a maintained driver compatible with the exact kernel and confirm
monitor mode before using PiSAT.

Install and build:

```bash
chmod +x scripts/install_dependencies.sh
./scripts/install_dependencies.sh
sudoedit /etc/pisat/pisat.conf
sudo systemctl enable --now pisat
```

## SX126x LoRa HAT setup

PiSAT supports SX126x HATs that expose a **transparent UART data interface**
and M0/M1/AUX GPIO control, including common Waveshare-style SX1262/SX1268
HATs. It uses the C `pigpio` library directly to drive M0/M1 into normal mode
and waits for AUX before UART transmission. Configure both HATs with the
vendor's setup tool so they use the same frequency, address/network, air data
rate, packet size, and UART baud. PiSAT controls operating mode through GPIO
but does not rewrite vendor-specific radio registers.

On the Raspberry Pi:

```bash
sudo raspi-config
# Interface Options -> Serial Port:
#   login shell over serial: No
#   serial hardware enabled: Yes
sudo reboot
readlink -f /dev/serial0
```

The default BCM GPIO mapping is:

| HAT signal | Raspberry Pi signal | Physical pin |
|---|---|---|
| M0 | GPIO22 | 15 |
| M1 | GPIO27 | 13 |
| AUX | GPIO17 | 11 |
| HAT RX | GPIO14 / TXD | 8 |
| HAT TX | GPIO15 / RXD | 10 |
| GND | GND | 6 |

Use the HAT vendor's required power pin and voltage. Verify its pinout before
powering the board.

Set a random shared key and verify the UART device in `/etc/pisat/pisat.conf`:

```ini
lora_enabled=true
lora_device=/dev/serial0
lora_baud=9600
lora_node_id=pisat-field-01
lora_key=<random-shared-key-of-at-least-16-characters>
lora_allowed_controllers=pitak-field-01
lora_m0_gpio=22
lora_m1_gpio=27
lora_aux_gpio=17
lora_aux_active_high=true
lora_aux_timeout_ms=2000
lora_publish_interval_seconds=30
```

PiSAT disables pigpio's signal handlers and unauthenticated socket/FIFO
interfaces, then places M0/M1 low for normal transparent mode. If AUX does not reach its
configured ready level within the timeout, startup or transmission fails
instead of sending into a busy HAT. The packaged service runs as root for
direct `/dev/gpiomem` or `/dev/mem` access; do not run a separate `pigpiod`
instance for this process.

The key is converted to an AES-256 key with SHA-256. AES-GCM encrypts and
authenticates every frame, while persisted per-source nonces prevent replay
after restart. Radio metadata such as timing and frame length remains visible,
so use the system only where LoRa operation is lawful.

Every participant using the same `lora_key` must have a globally unique node
ID. Reusing a node ID can reuse an AES-GCM IV and destroy confidentiality and
authentication. PiSAT refuses generic/default node IDs.

`lora_key` is the dedicated PiSAT pairing key and should match
`PITAK_PISAT_KEY` only on authorized control panels. It must not be reused as
the PiTAK peer-messaging key. `lora_allowed_controllers` is a comma-separated
allowlist of PiTAK node IDs permitted to issue PiSAT commands.

Configure the matching PiTAK environment with separate control and peer keys:

```bash
export PITAK_NODE_ID=pitak-field-01
export PITAK_PISAT_NODE=pisat-field-01
export PITAK_PISAT_KEY='<same secret as PiSAT lora_key>'
export PITAK_NETWORK_KEY='<different peer messaging/discovery secret>'
export PITAK_NAME='Field Team 01'
export PITAK_LORA_FREQUENCY=915000000
export PITAK_LORA_CHANNEL=0
export PITAK_LORA_NETWORK=field-network
export PITAK_LORA_ADDRESS=pitak-field-01
```

Each PiTAK sharing `PITAK_NETWORK_KEY` must also have a globally unique
`PITAK_NODE_ID`. PiTAK refuses secure traffic when the peer and PiSAT keys are
identical.

## CLI

```bash
sudo pisat --config /etc/pisat/pisat.conf monitor on --channel 6
sudo pisat --config /etc/pisat/pisat.conf monitor status
sudo pisat --config /etc/pisat/pisat.conf capture \
  --engine tcpdump --output /var/lib/pisat/session.pcap
sudo pisat --config /etc/pisat/pisat.conf capture \
  --engine airodump --output /var/lib/pisat/session
sudo pisat --config /etc/pisat/pisat.conf capture \
  --engine wireshark --output /var/lib/pisat/session.pcapng
sudo pisat --config /etc/pisat/pisat.conf monitor off
```

The `wireshark` engine invokes Wireshark's headless capture component,
`dumpcap`. Captures can later be opened in Wireshark or inspected with
`tshark`.

## API

### LoRa protocol

LoRa is the default control and data surface. Each newline-delimited frame is
at most `lora_max_frame_bytes` (220 by default):

```text
P2|SOURCE|TARGET|NONCE|TYPE|CIPHERTEXT_B64|TAG_B64
```

Payloads use AES-256-GCM. The AES key is SHA-256 of `lora_key`; the
authenticated header is the first five fields. The 12-byte IV is derived from
the first four bytes of SHA-256(`SOURCE`) plus the 8-byte big-endian nonce.
`NONCE` must be greater than every nonce previously accepted from that source,
and PiSAT persists a separate high-water mark per source. Responses use `OK`
or `ERR`; their decrypted payload begins with the original request nonce.
Periodic encrypted status publications use `TARGET=*` and type `EVENT`.
Ciphertext and tags use standard padded Base64.

| Command | Arguments | Result |
|---|---|---|
| `PING` | empty | `PONG` |
| `STATUS` | empty | monitor, capture engine/state, device count |
| `DEVICES` | `offset,limit` | one compact device record per response |
| `MONITOR` | `ON,channel` or `OFF` | changes adapter mode and survey state |
| `CAPTURE` | `START,tcpdump`, `START,airodump`, `START,wireshark`, or `STOP` | controls local capture |

Generate a correctly encrypted request on a trusted controller:

```bash
pisat --config controller.conf lora-frame \
  --target pisat-field-01 --nonce 1001 --command STATUS

pisat --config controller.conf lora-frame \
  --target pisat-field-01 --nonce 1002 --command MONITOR --args ON,6

pisat --config controller.conf lora-frame \
  --target pisat-field-01 --nonce 1003 --command DEVICES --args 0,1

pisat --config controller.conf lora-frame \
  --target pisat-field-01 --nonce 1004 --command CAPTURE --args START,tcpdump
```

Send the generated line through the controller's paired transparent-UART LoRa
modem. Raw pcap/pcapng files remain on the Pi because they are not practical
to transfer over low-bandwidth LoRa; LoRa publishes status and compact device
records.

Keep `/etc/pisat/pisat.conf` root-readable only (`chmod 600`); it contains the
shared LoRa key. CMake installs it with this permission by default.

### Optional HTTP diagnostics

Set `http_enabled=true`. If binding beyond localhost, set a strong
`api_token` and place the API behind a trusted VPN or TLS reverse proxy; the
built-in HTTP server does not provide TLS.

Read endpoints:

```text
GET /health
GET /api/v1/status
GET /api/v1/devices
```

All `/api/v1` endpoints require `Authorization: Bearer TOKEN` when `api_token`
is configured (`/health` remains public):

```bash
curl -H "Authorization: Bearer $PISAT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"channel":6}' \
  http://raspberrypi:8080/api/v1/monitor

curl -H "Authorization: Bearer $PISAT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"engine":"tcpdump","output":"/var/lib/pisat/lab.pcap"}' \
  http://raspberrypi:8080/api/v1/capture/start

curl -H "Authorization: Bearer $PISAT_TOKEN" \
  http://raspberrypi:8080/api/v1/devices

curl -H "Authorization: Bearer $PISAT_TOKEN" \
  -X POST http://raspberrypi:8080/api/v1/capture/stop

curl -H "Authorization: Bearer $PISAT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}' \
  http://raspberrypi:8080/api/v1/monitor
```

`GET /api/v1/devices` is the headless publication surface. It returns updated
access-point and station records observed by the background `airodump-ng`
survey. A remote collector can poll this endpoint and republish the JSON to
MQTT, a database, or another telemetry system.

## Capture behavior

| Engine | Executable | Output |
|---|---|---|
| `tcpdump` | `tcpdump` | pcap |
| `airodump` | `airodump-ng` | pcap and CSV files using the supplied prefix |
| `wireshark` | `dumpcap` | pcapng |

Changing out of monitor mode stops both the active capture and device survey.
Output paths submitted through the API must remain under `data_directory`.
For `airodump`, the supplied output is a prefix; status reports the generated
`PREFIX-01.cap` capture path.

## Build manually

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
sudo cmake --install build
```
