import socket
import struct
import math as m

from kivy.app import App
from kivy.properties import ObjectProperty
from kivy.clock import Clock
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.carousel import Carousel
from kivy.uix.button import Button

class DeviMoteVolume(BoxLayout):
    vol_slider: ObjectProperty(None)

    def set_byte (self, byte):
        self.vol_slider.value = byte

class DeviMoteWidget(GridLayout):
    channels  = ObjectProperty(None)
    volume    = ObjectProperty(None)
    stat_line = ObjectProperty(None)
    sw_power  = ObjectProperty(None)
    sw_mute   = ObjectProperty(None)

    def populate_channels(self, ch_list):
        for channel in ch_list:
            self.channels.values.append(ch_list[channel])

    def set_volume(self, byte):
        self.volume.set_byte(byte)

    def update(self, status):
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
            self.sw_mute.state  = status['muted'] and 'down' or 'normal'
            self.volume.set_byte(status['volume'])
            if not self.channels.values:
                self.populate_channels(status['ch_list'])
            self.channels.text = status['ch_list'][status['channel']]
        else:
            self.stat_line.text  = 'Status: Not connected'

class DeviMoteBackEnd():
    UDP_PORT_STATUS = 45454
    UDP_PORT_CMD    = 45455
    VOLUME_LIMIT    = -10

    def __init__(self):
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

    def crc16(self, data : bytearray):
        if data is None :
            return 0
        crc = 0xFFFF
        for i in range(len(data)):
            crc ^= data[i] << 8
            for j in range(8):
                if (crc & 0x8000) > 0:
                    crc =(crc << 1) ^ 0x1021
                else:
                    crc = crc << 1
        return crc & 0xFFFF

    def _send_command(self, data: bytearray):
        if not (self.status['connected'] and self.status['ip']):
            return
        sock = socket.socket(socket.AF_INET,    # Internet
                             socket.SOCK_DGRAM) # UDP
        data[0] = 0x44
        data[1] = 0x72
        for i in range(4):
            data[3] = self.packet_cnt
            data[5] = self.packet_cnt >> 1
            self.packet_cnt += 1
            crc = self.crc16(data[0:12])
            data[12] = (crc & 0xff00) >> 8
            data[13] = (crc & 0x00ff)                
            sock.sendto(data, (self.status['ip'], self.UDP_PORT_CMD))

    def toggle_power(self):
        data = bytearray(142)
        data[6] = int(not self.status['power'])
        data[7] = 0x01
        self._send_command(data)

    def toggle_mute(self):
        data = bytearray(142)
        data[6] = int(not self.status['muted'])
        data[7] = 0x07
        self._send_command(data)

    def set_volume(self, dB_value):

        if dB_value > self.VOLUME_LIMIT:
            dB_value = self.VOLUME_LIMIT

        def _dB_convert(dB_value):
            dB_abs = m.fabs(dB_value)
            if dB_abs == 0:
                return 0
            elif dB_abs == 0.5:
                return 0x3f00
            else:
                return (256 >> m.ceil(1 + m.log(dB_abs, 2))) + _dB_convert(dB_abs - 0.5)

        volume = _dB_convert(dB_value)

        if dB_value < 0:
            volume |= 0x8000

        data = bytearray(142)
        data[6] = 0x00
        data[7] = 0x04
        data[8] = (volume & 0xff00) >> 8
        data[9] = (volume & 0x00ff)
        self._send_command(data)
    
    def set_output(self, output):
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
        self.status['crc_ok']  = (self.crc16(data[:-2]) == struct.unpack('>H',data[-2:])[0])

        return self.status

class DeviMoteApp(App):

    def _powered(self, dt):
        self.status['booting'] = False

    def toggle_power_callback(self, instance):
        if self.status['booting']:
            return
        if not self.status['power']:
            self.status['booting'] = True
            Clock.schedule_once(self._powered, 20)
        self.backend.toggle_power()
        
    def toggle_mute_callback(self, instance):
        self.backend.toggle_mute()

    def set_volume_callback(self, instance, value):
        if value != self.status['volume']:
            self.backend.set_volume((value-195.0) / 2)

    def set_output_callback(self, instance, text):
        for channel in self.status['ch_list']:
            if text == self.status['ch_list'][channel]:
                output = channel
                break
        if output != self.status['channel']:
            self.backend.set_output(output)

    def build(self):
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

    def update(self, dt):
        self.status = self.backend.update()
        if self.status['power']:
            self._powered(0)
        self.gui.update(self.status)

    def report(self, status):
        if not status['crc_ok']:
            print ('[CRC ERROR]')
            return
        if status['connected']:
            print (
                "[{}] {} ({}), volume: {}dB {} {}".format(
                    "ON " if status['power'] else "OFF",
                    status['dev_name'],
                    status['ip'],
                    (status['volume'] - 195) / 2.0,
                    status['ch_list'][status['channel']],
                    "[M]" if status['muted'] else ""
                )
            )

if __name__ == '__main__':
    DeviMoteApp().run()
