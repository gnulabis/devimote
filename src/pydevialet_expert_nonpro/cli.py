# SPDX-FileCopyrightText: 2026 Renaud Bruyeron <bruyeron@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

'''CLI remote control for Devialet Expert amplifiers'''

import contextlib
import json
import os
import socket
from pathlib import Path

import click
from dotenv import load_dotenv

from pydevialet_expert_nonpro import DeviMoteBackEnd

load_dotenv()


def _volume_db(raw: int) -> float:
    return (raw - 195) / 2.0


def _state_path() -> Path:
    return Path(click.get_app_dir('pydevialet-expert-nonpro')) / 'state.json'


def _load_packet_cnt(ip: str) -> int:
    try:
        state = json.loads(_state_path().read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return 0
    return int(state.get(ip, 0)) % 0x10000


def _save_packet_cnt(ip: str, packet_cnt: int) -> None:
    path = _state_path()
    try:
        state = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        state = {}
    state[ip] = packet_cnt
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state))


def _connect() -> DeviMoteBackEnd:
    backend = DeviMoteBackEnd()
    expected_ip = os.getenv('DEVIALET_IP')
    s = backend.update()
    if not s['connected']:
        raise click.ClickException(
            'Amplifier not found (timeout waiting for UDP broadcast on port 45454)'
        )
    if expected_ip:
        resolved = socket.gethostbyname(expected_ip)
        if s['ip'] != resolved:
            click.echo(
                f"Warning: expected {expected_ip} ({resolved}), connected to {s['ip']}",
                err=True,
            )
    backend.packet_cnt = _load_packet_cnt(s['ip'])
    return backend


@contextlib.contextmanager
def _session():
    '''Connect and persist the packet counter afterwards.

    Each CLI run creates a fresh backend, so without this the 16-bit packet counter
    would restart at 0 on every invocation. Testing showed the amplifier accepts a
    counter reset, so this is a safeguard that keeps the sequence continuous, just
    in case.
    '''
    backend = _connect()
    try:
        yield backend
    finally:
        _save_packet_cnt(backend.status['ip'], backend.packet_cnt)


@click.group()
def main():
    '''CLI remote control for Devialet Expert amplifiers'''


@main.command()
def status():
    '''Show current amplifier status'''
    backend = _connect()
    s = backend.status
    ch_name = s['ch_list'].get(s['channel'], f"#{s['channel']}").strip()
    sources = ', '.join(f"{n.strip()} ({i})" for i, n in sorted(s['ch_list'].items()))
    click.echo(f"Device:  {s['dev_name'].strip()}")
    click.echo(f"IP:      {s['ip']}")
    click.echo(f"Power:   {'ON' if s['power'] else 'STANDBY'}")
    click.echo(f"Volume:  {_volume_db(s['volume']):+.1f} dB")
    click.echo(f"Muted:   {'Yes' if s['muted'] else 'No'}")
    click.echo(f"Source:  {ch_name} ({s['channel']})")
    click.echo(f"Sources: {sources}")
    click.echo(f"State:   {_state_path()} (packet_cnt={backend.packet_cnt})")


@main.command()
@click.argument('db', type=float)
def volume(db):
    '''Set volume in dB. Use -- before negative values: volume -- -15'''
    if db > DeviMoteBackEnd.VOLUME_LIMIT:
        raise click.ClickException(
            f"Volume {db:+.1f} dB exceeds limit {DeviMoteBackEnd.VOLUME_LIMIT:+.1f} dB"
        )
    with _session() as backend:
        backend.set_volume(db)
    click.echo(f"Volume set to {db:+.1f} dB")


@main.command()
def mute():
    '''Toggle mute on/off'''
    with _session() as backend:
        backend.toggle_mute()
    click.echo('Mute toggled')


@main.command()
def power():
    '''Toggle power (on/standby)'''
    with _session() as backend:
        backend.toggle_power()
    click.echo('Power toggled')


@main.command()
@click.argument('name')
def source(name):
    '''Select input source by name (case-insensitive partial match)'''
    with _session() as backend:
        ch_list = backend.status['ch_list']
        matches = {idx: n for idx, n in ch_list.items() if name.lower() in n.lower()}
        if not matches:
            available = ', '.join(n.strip() for n in ch_list.values())
            raise click.ClickException(f"No source matching '{name}'. Available: {available}")
        if len(matches) > 1:
            found = ', '.join(f"{n.strip()} ({i})" for i, n in sorted(matches.items()))
            raise click.ClickException(f"Ambiguous source '{name}', matches: {found}")
        idx, n = next(iter(matches.items()))
        backend.set_output(idx)
    click.echo(f"Source set to {n.strip()}")
