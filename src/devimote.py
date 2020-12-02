'''An unofficial remote control application for Devialet Expert amplifiers'''

import socket
import struct
import math as m

from kivy.app import App
from kivy.properties import ObjectProperty # pylint: disable=no-name-in-module
from kivy.clock import Clock
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout

class DeviMoteVolume(BoxLayout):
    '''Wrapper class around BoxLayout'''
    vol_slider: ObjectProperty(None)

    def set_byte (self, byte):
        '''Function to adjust the volume slider'''
        self.vol_slider.value = byte

class DeviMoteWidget(GridLayout):
    '''Top-level widget'''
    channels  = ObjectProperty(None)
    volume    = ObjectProperty(None)
    stat_line = ObjectProperty(None)
    sw_power  = ObjectProperty(None)
    sw_mute   = ObjectProperty(None)

    def set_volume(self, byte):
        '''Function to adjust the volume'''
        self.volume.set_byte(byte)

    def update(self, status):
        '''Function to update all GUI elements based on current status'''
        if status and status['connected']:
            self.stat_line.text = 'Status: Connected'
            if status['power']:
                self.sw_power.state = 'down'
                self.sw_power.text  = 'ON'
                self.sw_power.background_color = [1, 1, 1, 1]
            elif status['booting']:
                self.sw_power.state = 'down'
                self.sw_power.text  = 'BOOTING'
                self.sw_power.background_color = [.25, .25, .25, 1]
            else:
                self.sw_power.state = 'normal'
                self.sw_power.text  = 'STANDBY'
                self.sw_power.background_color = [1, 1, 1, 1]
            self.sw_mute.state  = 'down' if status['muted'] else 'normal'
            self.volume.set_byte(status['volume'])
            if not self.channels.values:
                for channel in status['ch_list']:
                    self.channels.values.append(status['ch_list'][channel])
            self.channels.text = status['ch_list'][status['channel']]
        else:
            self.stat_line.text  = 'Status: Not connected'

def _crc16(data : bytearray):
    '''Internal function to calculate a CRC-16/CCITT-FALSE from the given bytearray'''
    if data is None :
        return 0
    crc = 0xFFFF
    for i in enumerate(data):
        crc ^= data[i[0]] << 8
        for _ in range(8):
            if (crc & 0x8000) > 0:
                crc =(crc << 1) ^ 0x1021
            else:
                crc = crc << 1
    return crc & 0xFFFF

class DeviMoteBackEnd():
    '''Backend class handling all control and status monitoring'''
    UDP_PORT_STATUS = 45454
    UDP_PORT_CMD    = 45455
    VOLUME_LIMIT    = -10

    def __init__(self):
        '''Backend constructor with default initial values'''
        self.status = {}
        self.status['dev_name'] = 'Unknown'
        self.status['ip'] = None
        self.status['ch_list']  = {}
        self.status['power'] = False
        self.status['muted'] = False
        self.status['channel'] = 0
        self.status['volume'] = 0
        self.status['connected'] = False
        self.status['crc_ok'] = False
        self.packet_cnt = 0

    def _send_command(self, data: bytearray):
        '''Internal function that builds and transmits a UDP packet command to the amplifier'''
        if not (self.status['connected'] and self.status['ip']):
            return
        sock = socket.socket(socket.AF_INET,    # Internet
                             socket.SOCK_DGRAM) # UDP
        data[0] = 0x44
        data[1] = 0x72
        for _ in range(4):
            data[3] = self.packet_cnt
            data[5] = self.packet_cnt >> 1
            self.packet_cnt += 1
            crc = _crc16(data[0:12])
            data[12] = (crc & 0xff00) >> 8
            data[13] = (crc & 0x00ff)
            sock.sendto(data, (self.status['ip'], self.UDP_PORT_CMD))

    def toggle_power(self):
        '''Function for toggling the power status'''
        data = bytearray(142)
        data[6] = int(not self.status['power'])
        data[7] = 0x01
        self._send_command(data)

    def toggle_mute(self):
        '''Function for toggling the mute status'''
        data = bytearray(142)
        data[6] = int(not self.status['muted'])
        data[7] = 0x07
        self._send_command(data)

    def set_volume(self, db_value):
        '''Function for changing the volume'''

        if db_value > self.VOLUME_LIMIT:
            db_value = self.VOLUME_LIMIT

        def _db_convert(db_value):
            '''Internal function to convert dB to a 16-bit representation used by set_volume'''
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
        data[9] = (volume & 0x00ff)
        self._send_command(data)

    def set_output(self, output):
        '''Function for changing the output'''
        out_val = 0x4000 | (output << 5)
        data = bytearray(142)
        data[6] = 0x00
        data[7] = 0x05
        data[8] = (out_val & 0xff00) >> 8
        if output > 7:
            data[9] = (out_val & 0x00ff) >> 1
        else:
            data[9] = (out_val & 0x00ff)
        self._send_command(data)

    def update(self):
        '''Try to get UDP status packet and decode it'''
        sock = socket.socket(socket.AF_INET,    # Internet
                             socket.SOCK_DGRAM) # UDP
        sock.bind(('', self.UDP_PORT_STATUS))
        sock.settimeout(2)
        try:
            data, addr = sock.recvfrom(512) # buffer size is 512 bytes
        except socket.timeout:
            self.status['connected'] = False
            return self.status
        self.status['connected'] = True
        self.status['ip'] = addr[0]
        self.status['dev_name'] = data[19:50].decode('UTF-8')
        for i in range(0,15):
            enabled = int(chr(data[52+i*17]))
            if enabled:
                self.status['ch_list'][i] = data[53+i*17:52+(i+1)*17].decode('UTF-8')
        self.status['power']   = (data[307] & 0x80) != 0
        self.status['muted']   = (data[308] & 0x2) != 0
        self.status['channel'] = (data[308] & 0x3c) >> 2
        self.status['volume']  =  data[310]
        self.status['crc_ok']  = (_crc16(data[:-2]) == struct.unpack('>H',data[-2:])[0])

        return self.status

class DeviMoteApp(App):
    '''Top-level class combining the backend and the top-level widget'''
    def __init__(self):
        '''Constructor'''
        super().__init__()
        self.gui = None
        self.backend = None
        self.status = None

    def _powered(self, _dt):
        '''Internal function to use during booting'''
        self.status['booting'] = False

    def toggle_power_callback(self, _instance):
        '''Callback function for toggling power'''
        if self.status['booting']:
            return
        if not self.status['power']:
            self.status['booting'] = True
            Clock.schedule_once(self._powered, 20)
        self.backend.toggle_power()

    def toggle_mute_callback(self, _instance):
        '''Callback function for toggling mute'''
        self.backend.toggle_mute()

    def set_volume_callback(self, _instance, value):
        '''Callback function for changing the volume'''
        if value != self.status['volume']:
            self.backend.set_volume((value-195.0) / 2)

    def set_output_callback(self, _instance, text):
        '''Callback function for changing the output'''
        for channel in self.status['ch_list']:
            if text == self.status['ch_list'][channel]:
                output = channel
                break
        if output != self.status['channel']:
            self.backend.set_output(output)

    def build(self):
        '''Kivy build function, runs once'''
        self.gui = DeviMoteWidget()
        self.backend = DeviMoteBackEnd()
        self.status = self.backend.update()
        self._powered(0)
        self.gui.update(self.status)
        self.gui.sw_power.bind(on_press=self.toggle_power_callback)
        self.gui.sw_mute.bind(on_press=self.toggle_mute_callback)
        self.gui.volume.vol_slider.bind(value=self.set_volume_callback)
        self.gui.channels.bind(text=self.set_output_callback)
        Clock.schedule_interval(self.update, 0.1)
        return self.gui

    def update(self, _dt):
        '''Function to update both the backend and the GUI. Scheduled to run periodically'''
        self.status = self.backend.update()
        if self.status['power']:
            self._powered(0)
        self.gui.update(self.status)

    def report(self):
        '''Pretty-print current status'''
        if not self.status['crc_ok']:
            print ('[CRC ERROR]')
            return
        if self.status['connected']:
            print (
                "[{}] {} ({}), volume: {}dB {} {}".format(
                    "ON " if self.status['power'] else "OFF",
                    self.status['dev_name'],
                    self.status['ip'],
                    (self.status['volume'] - 195) / 2.0,
                    self.status['ch_list'][self.status['channel']],
                    "[M]" if self.status['muted'] else ""
                )
            )

if __name__ == '__main__':
    DeviMoteApp().run()
