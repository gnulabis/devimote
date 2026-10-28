# SPDX-FileCopyrightText: 2020-2026 Dimitris Lampridis <dlampridis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

'''UDP communication backend for Devialet Expert (non-Pro) amplifiers.

The amplifier broadcasts a 512-byte status packet on UDP port 45454 at ~10 Hz and
accepts 142-byte command packets on UDP port 45455. The protocol has no official
documentation; it was reverse-engineered via Wireshark.
'''

import binascii
import math as m
import socket
import struct
from typing import Optional


def _crc16(data: bytearray) -> int:
    '''CRC-16/CCITT-FALSE checksum over ``data``.'''
    return binascii.crc_hqx(data, 0xFFFF)


class DeviMoteBackEnd:
    '''Control and status monitoring for a Devialet Expert (non-Pro) amplifier.

    The class is pure standard library and free of any GUI/framework dependency, so
    it can be embedded in a CLI, a Kivy GUI, or a Home Assistant integration alike.
    All network calls are blocking; callers that need async behaviour should run them
    on a worker thread (e.g. Home Assistant's executor).
    '''

    UDP_PORT_STATUS = 45454
    UDP_PORT_CMD = 45455
    VOLUME_LIMIT = -10

    def __init__(self, host: Optional[str] = None) -> None:
        '''Create a backend, optionally targeting ``host`` (hostname or IP).

        When ``host`` is given it is used as the command destination until the device
        is discovered from a status broadcast, after which the discovered IP wins.
        '''
        self._configured_host = host
        self.status: dict = {}
        self.status['dev_name'] = 'Unknown'
        self.status['ip'] = None
        self.status['ch_list'] = {}
        self.status['power'] = False
        self.status['muted'] = False
        self.status['channel'] = 0
        self.status['volume'] = 0
        self.status['connected'] = False
        self.status['crc_ok'] = False
        self.packet_cnt = 0

    def _send_command(self, data: bytearray) -> None:
        '''Build and transmit a UDP command packet to the amplifier.

        The packet is framed with a ``0x44 0x72`` header and a CRC-16/CCITT-FALSE
        checksum over the first 12 bytes, then sent 4 times for reliability (UDP).

        Bytes 2-3 carry a 16-bit big-endian packet counter and bytes 4-5 a 16-bit
        command counter equal to ``packet_cnt >> 1`` (observed in captures of the
        official app, where the counter ran well past 255 without wrapping).
        '''
        ip = self.status.get('ip') or self._configured_host
        if not ip:
            return
        sock = socket.socket(socket.AF_INET,    # Internet
                             socket.SOCK_DGRAM)  # UDP
        data[0] = 0x44
        data[1] = 0x72
        for _ in range(4):
            data[2:4] = self.packet_cnt.to_bytes(2, 'big')
            data[4:6] = (self.packet_cnt >> 1).to_bytes(2, 'big')
            self.packet_cnt = (self.packet_cnt + 1) % 0x10000
            crc = _crc16(data[0:12])
            data[12] = (crc & 0xff00) >> 8
            data[13] = crc & 0x00ff
            sock.sendto(data, (ip, self.UDP_PORT_CMD))

    def toggle_power(self) -> None:
        '''Toggle the amplifier power (on / standby).'''
        data = bytearray(142)
        data[6] = int(not self.status['power'])
        data[7] = 0x01
        self._send_command(data)

    def toggle_mute(self) -> None:
        '''Toggle the mute state.'''
        data = bytearray(142)
        data[6] = int(not self.status['muted'])
        data[7] = 0x07
        self._send_command(data)

    def set_volume(self, db_value: float) -> None:
        '''Set the volume to ``db_value`` dB.

        Values above ``VOLUME_LIMIT`` are clamped. The hardware resolution is 0.5 dB;
        the value is rounded to the nearest half-step because ``_db_convert`` only
        terminates on multiples of 0.5.
        '''
        db_value = min(db_value, self.VOLUME_LIMIT)
        db_value = round(db_value * 2) / 2

        def _db_convert(db_value: float) -> int:
            '''Convert a dB magnitude to the 16-bit representation used on the wire.'''
            db_abs = m.fabs(db_value)
            if db_abs == 0:
                retval = 0
            elif db_abs == 0.5:
                retval = 0x3f00
            else:
                retval = (256 >> m.ceil(1 + m.log(db_abs, 2))) + _db_convert(db_abs - 0.5)
            return retval

        volume = _db_convert(db_value)

        if db_value < 0:
            volume |= 0x8000

        data = bytearray(142)
        data[6] = 0x00
        data[7] = 0x04
        data[8] = (volume & 0xff00) >> 8
        data[9] = volume & 0x00ff
        self._send_command(data)

    def set_output(self, output: int) -> None:
        '''Select the input source by channel index ``output``.'''
        out_val = 0x4000 | (output << 5)
        data = bytearray(142)
        data[6] = 0x00
        data[7] = 0x05
        data[8] = (out_val & 0xff00) >> 8
        if output > 7:
            data[9] = (out_val & 0x00ff) >> 1
        else:
            data[9] = out_val & 0x00ff
        self._send_command(data)

    def update(self) -> dict:
        '''Receive one status broadcast (2 s timeout) and decode it into ``self.status``.

        Returns ``self.status``. On timeout, marks the device disconnected and returns
        the (stale) status unchanged otherwise.
        '''
        sock = socket.socket(socket.AF_INET,    # Internet
                             socket.SOCK_DGRAM)  # UDP
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.UDP_PORT_STATUS))
        sock.settimeout(2)
        try:
            data, addr = sock.recvfrom(512)  # buffer size is 512 bytes
        except socket.timeout:
            self.status['connected'] = False
            return self.status
        self.status['connected'] = True
        self.status['ip'] = addr[0]
        # Magic byte offsets below are taken from the reverse-engineered status frame.
        self.status['dev_name'] = data[19:50].decode('UTF-8')
        self.status['ch_list'] = {}
        for i in range(0, 15):
            enabled = int(chr(data[52 + i * 17]))
            if enabled:
                self.status['ch_list'][i] = data[53 + i * 17:52 + (i + 1) * 17].decode('UTF-8')
        self.status['power'] = (data[307] & 0x80) != 0
        self.status['muted'] = (data[308] & 0x2) != 0
        self.status['channel'] = (data[308] & 0x3c) >> 2
        self.status['volume'] = data[310]
        self.status['crc_ok'] = _crc16(data[:-2]) == struct.unpack('>H', data[-2:])[0]

        return self.status


# Cleaner public alias; the original name is kept for backward compatibility with the
# Kivy GUI and Home Assistant integration that already import DeviMoteBackEnd.
DevialetExpertNonPro = DeviMoteBackEnd
