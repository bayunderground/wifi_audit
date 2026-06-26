# CLAUDE.md

## Project Overview

This project is a **modular WPA2-Personal (PSK) Wi-Fi security auditing framework** intended **only for authorized testing of networks owned by the operator**.

The project is designed for:

* Raspberry Pi 5
* Kali Linux
* Python 3.12+
* One management interface (SSH)
* One dedicated Wi-Fi adapter operating in monitor mode

The architecture emphasizes:

* clean separation of responsibilities
* event-driven design
* persistent state
* resumability
* unit testing
* minimal shell scripting
* maintainability

The project is **not** intended to be a collection of shell scripts.

---

# Goals

The application shall:

1. Discover nearby access points.
2. Filter APs according to configuration.
3. Capture WPA handshakes and/or PMKIDs.
4. Verify captures.
5. Export `.22000` files.
6. Crack hashes locally or on another machine.
7. Produce a concise report.

---

# Scope

Supported:

* WPA2-Personal (PSK)

Not supported:

* WPA-Enterprise
* WEP
* WPA3-specific attacks
* Evil Twin
* Rogue AP
* Network exploitation
* Client exploitation

---

# Architecture

```
main.py
    │
    ▼
Scheduler
    │
    ├──────── Scanner
    │
    ├──────── Capture
    │
    ├──────── Verification
    │
    ├──────── Converter
    │
    ├──────── Cracking
    │
    └──────── Report
```

Every module has a single responsibility.

Modules communicate through strongly typed Python objects.

---

# Design Principles

## Never pass dictionaries

Use dataclasses.

Correct:

```python
AuditTarget(...)
```

Wrong:

```python
{
    "bssid": "...",
    "state": ...
}
```

---

## Never call subprocess directly from business logic

Create wrappers.

Good:

```
audit/capture/backend.py
```

Bad:

```python
subprocess.run(...)
```

inside scheduler.

---

## Keep modules independent

Scanner must never know about:

* capture
* cracking
* reporting

Capture must never know about:

* scheduler internals
* reporting

---

## Dependency direction

```
main

↓

scheduler

↓

scanner
capture

↓

backend wrappers
```

Never reverse dependencies.

---

# State Machine

Allowed AP states:

```
DISCOVERED

↓

WAITING_FOR_CLIENT

↓

CAPTURING

↓

VERIFYING

↓

READY_TO_CRACK

↓

CRACKED
```

Possible transitions:

```
DISCOVERED
    ├──► WAITING_FOR_CLIENT
    └──► CAPTURING

WAITING_FOR_CLIENT
    └──► CAPTURING

CAPTURING
    ├──► VERIFYING
    └──► WAITING_FOR_CLIENT

VERIFYING
    ├──► READY_TO_CRACK
    └──► WAITING_FOR_CLIENT

READY_TO_CRACK
    └──► CRACKED
```

State transitions must occur only through the scheduler.

Never mutate `.state` directly outside the scheduler.

---

# Persistent State

Everything important must survive reboot.

Persistent:

* AP state
* attempts
* timestamps
* capture paths
* hash paths
* cracked password

Do not persist:

* temporary subprocess state
* monitor mode status
* running processes

---

# Scanner

Scanner responsibilities:

* execute `iw`
* parse output
* produce `AccessPoint`
* apply whitelist
* apply blacklist

Scanner must **not**

* enable monitor mode
* capture traffic
* crack passwords

---

# Monitor Manager

Responsible only for:

* enable monitor mode
* disable monitor mode
* change channel

Nothing else.

---

# Capture

Capture module only controls capture sessions.

Responsibilities:

* start capture
* stop capture
* detect handshake availability
* expose events

It should **not** verify captures.

---

# Verification

Verification determines whether a capture is usable.

Responsibilities:

* validate capture
* produce `.22000`

No scheduler logic.

---

# Cracking

Input:

```
.22000
```

Output:

```
password
```

Use Hashcat mask mode.

Do **not** generate wordlists.

Preferred mask:

```
?d?d?d?d?d?d?d?d
```

---

# Reporting

Reports should contain only:

```
ESSID

BSSID

PASSWORD
```

If unavailable:

```
not found
```

or

```
no handshake
```

---

# Configuration

Never hardcode:

* interface names
* regexes
* paths
* timeouts

Everything belongs in:

```
config/config.yaml
```

---

# Logging

Never use:

```python
print(...)
```

Always:

```python
logger = get_logger(__name__)
```

Logging should be structured.

---

# Error Handling

Prefer exceptions over return codes.

Bad:

```python
return False
```

Good:

```python
raise CaptureFailed(...)
```

Exceptions should be domain-specific.

---

# Testing

Every module should have unit tests.

Mock:

* subprocess
* filesystem
* time

Never require:

* monitor mode
* Wi-Fi hardware
* root privileges

for unit tests.

---

# Code Style

Follow:

* PEP 8
* Black formatting
* Ruff linting
* type hints everywhere

Use:

```python
from __future__ import annotations
```

where appropriate.

---

# Preferred Standard Library

Prefer:

* pathlib
* enum
* dataclasses
* typing
* logging
* datetime
* heapq
* contextlib

Avoid unnecessary dependencies.

---

# Project Philosophy

This project prioritizes:

1. correctness
2. robustness
3. readability
4. testability
5. maintainability

Performance optimization comes only after correctness.

Small, composable modules are preferred over large classes.

Every component should be understandable and testable in isolation.

The long-term goal is a reliable, resumable Wi-Fi auditing framework whose orchestration is driven by persistent state rather than ad-hoc scripts.
