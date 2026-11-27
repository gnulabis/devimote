..
   SPDX-FileCopyrightText: 2020-2026 Dimitris Lampridis <dlampridis@gmail.com>
   SPDX-License-Identifier: CC0-1.0

=========
Changelog
=========

Unreleased
==========

Added
-----
- ``pydevialet_expert_nonpro``: the UDP communication code is now an installable,
  dependency-free Python library (PyPI distribution ``pydevialet-expert-nonpro``) that any
  application can reuse. Public API: ``DeviMoteBackEnd`` (alias ``DevialetExpertNonPro``).
- Unit tests covering the CRC-16/CCITT-FALSE checksum (incl. the canonical ``0x29B1`` check
  value), the dB volume encoding, and status-packet decoding — no amplifier required.

Fixed
-----
- The command packet counter is now 16 bits wide (bytes 2-3, with ``counter >> 1`` in bytes
  4-5), as seen in captures of the official app, and wraps at 65536. Previously only the
  low byte was written and the counter wrapped at 256.

Changed
-------
- Replaced the hand-rolled CRC-16/CCITT-FALSE with ``binascii.crc_hqx`` from the standard
  library (verified equivalent via the test vectors above).
- The Kivy GUI now lives in ``gui/devimote.py`` and imports the backend from the library
  instead of embedding it; it is a standalone script, not part of the published package.
- Project now builds with a ``pyproject.toml`` (setuptools, src layout). The GUI is
  available via the ``gui`` extra.
