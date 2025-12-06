<img src="https://raw.githubusercontent.com/KilDoomWise/OCNP/refs/heads/main/assets/logo.png" alt="logo">
OpenComputers Network Protocol — a modern, structured, deterministic networking standard for the OpenComputers mod.

<p align="center">
<a href="https://github.com/KilDoomWise/OCNP"><img src="https://img.shields.io/badge/Project-OCNP-blue?style=for-the-badge"></a>
<a href="https://github.com/KilDoomWise/OCNP/blob/main/LICENSE"><img src="https://img.shields.io/github/license/KilDoomWise/OCNP?style=for-the-badge"></a>
<a href="https://github.com/KilDoomWise/OCNP"><img src="https://img.shields.io/github/stars/KilDoomWise/OCNP?style=for-the-badge"></a>
<a href="https://github.com/KilDoomWise/OCNP"><img src="https://img.shields.io/github/last-commit/KilDoomWise/OCNP?style=for-the-badge"></a>
</p>

---

## Overview

**OCNP** is a unified network protocol designed to standardize communication inside OpenComputers environments.

It describes **how packets should be structured, validated and delivered**, making it possible to build complex decentralized networks (like OCN) or just use OCNP as a convenient packet format for smaller setups.

OCNP focuses on:

* Predictable packet format
* Safe multi-hop forwarding
* TTL and loop prevention
* UID-based anti-replay
* Deterministic behavior across nodes

OCNP **is not the network itself** — it is the protocol used by networks such as OCN.

---

## Key Features

* **Strict unified packet schema**
* **UID + timestamp anti-replay system**
* **TTL-based loop protection**
* **Multi-hop friendly**
* **Router and ISP-friendly design**
* **Lightweight Lua implementation**
* **Pure protocol — can work with any topology or system**

---

## Packet Structure (OCNP v1.1)

All packets follow the same schema:

```lua
{
  v = "1.1",
  uid = "<unique-id>",
  ts = <timestamp>,
  src = "a.b.c.d",
  dst = "a.b.c.d",
  ttl = 16,
  payload = {
    type = "<string>",
    data = <table or string>
  }
}
```

### Field definitions

| Field     | Description                                           |
| --------- | ----------------------------------------------------- |
| `v`       | Protocol version                                      |
| `uid`     | Unique packet identifier preventing replay/duplicates |
| `ts`      | Timestamp of creation                                 |
| `src`     | Source IP                                             |
| `dst`     | Destination IP                                        |
| `ttl`     | Decreases every hop; packet drops at 0                |
| `payload` | Application/user data                                 |

---

## UID Generation

OCNP uses deterministic UID generation:

```
UID = HEX(hash(src .. ":" .. seq .. ":" .. ts))
```

This ensures:

* deduplication across routers
* anti-replay security
* predictable log recovery

Length can be 4–8 hex characters.

---

## How OCNP Is Used

OCNP **does not prescribe a network architecture**.

It can be used in:

* Simple 1-hop LAN systems
* Multi-hop router chains
* Full OCN provider-based topologies
* Peer-to-peer systems
* Custom routing daemons

The protocol only defines **how packets look and how they must be handled**.
Everything else (routing tables, ISPs, IX nodes, topology) is the responsibility of the network (e.g., OCN).

---

## Responsibilities of OCNP

### OCNP **does**:

* Define packet format
* Define UID rules
* Define TTL rules
* Define what counts as a valid or invalid packet
* Define how nodes should validate packets

### OCNP **does NOT**:

* Define routing algorithms
* Define how networks discover peers
* Define ISP structure
* Define topology
* Define how nodes find each other
* Provide DNS
* Provide security layers or encryption

These belong to the network layer built *on top* (e.g., OCN).

---

## Example Workflow

```
App → OCNP encoder → (your router logic) → modem.send()
```

On receiving:

```
modem_message → OCNP validator → UID/TTL checks → router/logic
```

Routers/networks can choose any forwarding logic they want — OCNP only ensures packets are structured and safe.

---

## Version Compatibility

* **v1.1** supports UID + timestamp
* **v1.0** packets are accepted but lack those fields
* Routers may fall back or convert

---

## Why Use OCNP?

* Makes packets consistent across all programs
* Prevents loops and replay attacks
* Enables multi-hop networks
* Easy to debug due to strict schema
* Works even in extremely large OCN-like topologies

---

## Future Plans

* Optional reliability extensions
* Optional compression
* Optional encryption wrapper (outside protocol core)
* Performance optimizations

---

## License

This project is licensed under the MIT License.
