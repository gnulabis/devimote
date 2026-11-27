# SPDX-FileCopyrightText: 2026 Dimitris Lampridis <dlampridis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

'''Source selection tests: the channel index->float32 packet.'''

import pytest

from pydevialet_expert_nonpro import DeviMoteBackEnd


@pytest.mark.parametrize('output, expected', [
    (0, '00000000'),
    (1, '3f800000'),
    (2, '40000000'),
    (3, '40400000'),
    (4, '40800000'),
    (5, '40a00000'),
    (6, '40c00000'),
    (7, '40e00000'),
    (8, '41000000'),
    (9, '41100000'),
    (10, '41200000'),
    (11, '41300000'),
    (12, '41400000'),
    (13, '41500000'),
    (14, '41600000'),
])
def test_output_is_big_endian_float32(net, output, expected):
    '''A source command uses sub-command 0x05 with the index as a float32.'''
    DeviMoteBackEnd(host='192.0.2.10').set_output(output)
    data = net['sent'][0][0]
    assert data[6:8] == bytes([0x00, 0x05])
    assert data[8:12].hex() == expected
