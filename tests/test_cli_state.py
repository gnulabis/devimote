# SPDX-FileCopyrightText: 2026 Dimitris Lampridis <dlampridis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

'''CLI session-state tests: persisted per-IP packet counter load/save.'''

import pytest

pytest.importorskip('click')
pytest.importorskip('dotenv')

# pylint: disable=wrong-import-position
from pydevialet_expert_nonpro import cli


@pytest.fixture(autouse=True)
def state_dir(tmp_path, monkeypatch):
    '''Point the CLI state file at a temporary directory.'''
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    monkeypatch.setenv('APPDATA', str(tmp_path))
    monkeypatch.setenv('HOME', str(tmp_path))
    return tmp_path


def test_missing_state_starts_at_zero():
    '''With no state file the counter starts at 0.'''
    assert cli._load_packet_cnt('192.0.2.10') == 0  # pylint: disable=protected-access


def test_roundtrip_per_ip():
    '''Counters are stored per amplifier IP and do not overwrite each other.'''
    # pylint: disable=protected-access
    cli._save_packet_cnt('192.0.2.10', 300)
    cli._save_packet_cnt('192.0.2.11', 7)
    assert cli._load_packet_cnt('192.0.2.10') == 300
    assert cli._load_packet_cnt('192.0.2.11') == 7


def test_corrupt_state_starts_at_zero():
    '''Unparseable JSON falls back to 0 instead of raising.'''
    # pylint: disable=protected-access
    path = cli._state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{not json')
    assert cli._load_packet_cnt('192.0.2.10') == 0


def test_oversized_stored_counter_is_wrapped_to_16_bits():
    '''A stored value above 0xFFFF (e.g. a pre-fix or hand-edited file) wraps to 16 bits.'''
    # pylint: disable=protected-access
    cli._save_packet_cnt('192.0.2.10', 0x10005)
    assert cli._load_packet_cnt('192.0.2.10') == 5
