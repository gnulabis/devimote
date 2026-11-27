# SPDX-FileCopyrightText: 2020-2026 Dimitris Lampridis <dlampridis@gmail.com>
# SPDX-FileCopyrightText: 2026 Renaud Bruyeron <bruyeron@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

'''Volume encoding tests: clamping, 0.5 dB rounding, and the dB->float32 packet.'''

import pytest

from pydevialet_expert_nonpro import DeviMoteBackEnd


def _volume_packet(net, db_value):
    '''Send ``db_value`` and return the first transmitted command packet.'''
    backend = DeviMoteBackEnd(host='192.0.2.10')
    backend.set_volume(db_value)
    assert net['sent'], 'expected a volume command packet'
    return net['sent'][0][0]


def test_volume_command_opcode(net):
    '''A volume command uses sub-command 0x04 with byte 6 cleared.'''
    data = _volume_packet(net, -20.0)
    assert data[6] == 0x00
    assert data[7] == 0x04


def test_negative_volume_sets_sign_bit(net):
    '''Negative dB values set the float32 sign bit, the top bit of byte 8.'''
    data = _volume_packet(net, -20.0)
    assert data[8] & 0x80


def test_clamps_above_limit(net):
    '''Anything above VOLUME_LIMIT must encode identically to VOLUME_LIMIT itself.'''
    at_limit = _volume_packet(net, DeviMoteBackEnd.VOLUME_LIMIT)
    above_limit = _volume_packet(net, DeviMoteBackEnd.VOLUME_LIMIT + 5)
    assert at_limit == above_limit


def test_rounds_to_half_db_step(net):
    '''Volume is rounded to 0.5 dB: -20.3 -> -20.5 and -20.1 -> -20.0.'''
    assert _volume_packet(net, -20.3) == _volume_packet(net, -20.5)
    assert _volume_packet(net, -20.1) == _volume_packet(net, -20.0)


@pytest.mark.parametrize('db_value, expected', [
    (-10.0, 'c1200000'),
    (-20.0, 'c1a00000'),
    (-40.5, 'c2220000'),
    (-97.5, 'c2c30000'),
])
def test_volume_is_big_endian_float32(net, db_value, expected):
    '''Bytes 8-11 hold the dB value as a big-endian float32.'''
    assert _volume_packet(net, db_value)[8:12].hex() == expected
