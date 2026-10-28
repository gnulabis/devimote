# SPDX-FileCopyrightText: 2026 Dimitris Lampridis <dlampridis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

'''Command packet counter tests: 16-bit packet counter and its ``>> 1`` command counter.'''

from pydevialet_expert_nonpro import DeviMoteBackEnd


def _counters(packet):
    '''Return (packet counter, command counter) decoded from a command packet.'''
    return int.from_bytes(packet[2:4], 'big'), int.from_bytes(packet[4:6], 'big')


def _send_toggle(net, start):
    '''Send one command starting at counter ``start``; return its packets and the backend.'''
    backend = DeviMoteBackEnd(host='192.0.2.10')
    backend.packet_cnt = start
    backend.toggle_mute()
    return [pkt for pkt, _ in net['sent']], backend


def test_counter_increments_per_packet(net):
    '''Each command sends 4 packets with consecutive counters.'''
    packets, backend = _send_toggle(net, 0)
    assert [_counters(p)[0] for p in packets] == [0, 1, 2, 3]
    assert backend.packet_cnt == 4


def test_command_counter_is_half_packet_counter(net):
    '''Bytes 4-5 always hold ``packet counter >> 1``.'''
    packets, _ = _send_toggle(net, 10)
    assert [_counters(p)[1] for p in packets] == [5, 5, 6, 6]


def test_counter_does_not_wrap_at_256(net):
    '''The counter continues into the high byte instead of wrapping at 255.'''
    packets, backend = _send_toggle(net, 254)
    assert [_counters(p)[0] for p in packets] == [254, 255, 256, 257]
    assert packets[2][2:4] == bytes([0x01, 0x00])
    assert backend.packet_cnt == 258


def test_counter_wraps_at_16_bits(net):
    '''After 0xFFFF the counter wraps to 0 and the command counter follows.'''
    packets, backend = _send_toggle(net, 0xFFFE)
    assert [_counters(p)[0] for p in packets] == [0xFFFE, 0xFFFF, 0, 1]
    assert [_counters(p)[1] for p in packets] == [0x7FFF, 0x7FFF, 0, 0]
    assert backend.packet_cnt == 2


def test_crc_valid_across_counter_boundary(net):
    '''The CRC (bytes 12-13) is recomputed for every packet, including past 255.'''
    # pylint: disable=import-outside-toplevel
    from pydevialet_expert_nonpro.backend import _crc16
    packets, _ = _send_toggle(net, 254)
    for pkt in packets:
        assert _crc16(pkt[0:12]) == int.from_bytes(pkt[12:14], 'big')
