# Network Toolbelt

Network Toolbelt is an internal network-operations utility for working with network infrastructure from a local Python/Tkinter desktop interface.

It is currently optimized for Cisco networking equipment, but the app is intentionally named and structured more broadly so it can grow into a multi-vendor network operations toolkit over time.

It is designed for network engineers who need to safely run repeatable checks, collect command output, perform pre/post maintenance comparisons, map credentials to target devices, and run focused scanner workflows across multiple network devices.

The application is intentionally kept as a single-file utility, `cisco_toolbelt.py`, while still using organized internal classes, dataclasses, command policies, parsers, analyzers, and UI components.
