# OpenComputers Network Protocol (OCNP v1.1)

<img src="https://raw.githubusercontent.com/KilDoomWise/OCNP/refs/heads/main/assets/logo.png" alt="logo"/>

---

## Overview

**OCNP** is a unified packet format and validation standard for communication inside OpenComputers. It defines how packets should be structured, hashed, validated, and safely forwarded across multiple hops.

OCNP is **not** a network implementation. It is a **protocol layer** used by networks like OCN or by standalone systems.

OCNP focuses on:

* Consistent packet structure
* TTL-based loop protection
* UID‑based anti‑replay
* Deterministic validation rules
* Multi-hop friendliness
* Simple and lightweight Lua implementation

---

## Key Features

* Strict delimiter‑based packet schema
* UID generation based on sender, sequence number, and timestamp
* Hash-based corruption detection
* TTL enforcement on every hop
* Support for large data transmission via chunking
* Fully topology‑agnostic

---

## Packet Structure (OCNP v1.1)

OCNP packets are transmitted as **plain strings** with fields separated by the delimiter `|`.

### Packet layout

```
version | type | src | dst | seq | uid | ts | ttl | hash | payload
```

### Example

```
1.1|D|10.0.1.5|10.0.1.7|42|00AF12C3|12345|14|9F2A|hello world
```

### Field Definitions

| Field   | Description                       |
| ------- | --------------------------------- |
| version | Protocol version ("1.1")          |
| type    | Packet type (D/A/C/R/P/E/S/F/O)   |
| src     | Source address                    |
| dst     | Destination address               |
| seq     | Sequence number                   |
| uid     | Unique packet identifier          |
| ts      | Timestamp at creation             |
| ttl     | Time-To-Live counter              |
| hash    | Integrity checksum                |
| payload | Data (string or serialized table) |

---

## UID Generation

UID is generated exactly as defined in the Lua implementation:

```
base = src .. ":" .. seq .. ":" .. ts
hash = calculateHash(base)        -- 16-bit additive checksum
UID  = HEX(hash * 256 + (#base % 256))
```

UID ensures:

* Replay protection
* Duplicate detection
* Deterministic identification across routers

---

## Packet Hashing

OCNP uses a simple checksum to detect corrupted packets:

```
hash = sum(bytes of (header + payload)) % 65536
```

This is not a cryptographic function — it is only for integrity checking.

---

## TTL Behavior

Every forwarding node must decrement TTL by 1.

If TTL reaches 0 → the packet is dropped.

Routers do **not** modify `src`, `uid`, or any other fields.

---

## Packet Types

| Code | Name      | Description                  |
| ---- | --------- | ---------------------------- |
| D    | DATA      | Standard data packet         |
| A    | ACK       | Acknowledgement              |
| C    | CHUNK     | Chunk of large data transfer |
| R    | CHUNK_REQ | Request for missing chunk    |
| P    | PING      | Connectivity check           |
| E    | ERROR     | Error message                |
| S    | SYN       | Session start (optional)     |
| F    | FIN       | Session end (optional)       |
| O    | ORS       | Internal OCN service packet  |

---

## Large Data Handling (Chunking)

OCNP supports sending large strings by splitting them into smaller pieces.

### Chunk Format

Each chunk payload follows:

```
chunkId:totalChunks:totalSize:fileHash:chunkData
```

* Chunk IDs start from **0**.
* `fileHash` is the checksum of the entire original data.

### Assembly

The receiver stores chunks by index, concatenates them in order, and verifies `fileHash`.

---

## Limitations

From the current implementation:

* `MAX_PACKET_SIZE = 8192`
* `HEADER_OVERHEAD = 150`
* `CHUNK_SIZE = 7000`

Payloads larger than ~7 KB require chunking.

---

## Usage

### Sending a packet

```lua
OCNP.send(modem, 69, "10.0.0.1", "10.0.0.5", OCNP.TYPE.DATA, "hi")
```

### Parsing a packet

```lua
local parsed = OCNP.parsePacket(packet)
```

---

## What OCNP Defines / Does Not Define

### OCNP does:

* Define packet schema
* Validate structure
* Ensure integrity (hash)
* Enforce TTL
* Generate UID
* Provide chunking logic

### OCNP does **not**:

* Provide routing
* Discover peers
* Implement topology
* Offer addressing rules
* Include encryption
* Replace DNS or ISP systems

These belong to the network layer (e.g., OCN) built on top of OCNP.

---

## License

MIT License.
