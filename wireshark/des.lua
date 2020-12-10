-- SPDX-FileCopyrightText: 2020 Dimitris Lampridis <dlampridis@gmail.com>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

des_protocol = Proto("DES",  "Devialet Expert Status")

des_protocol.fields.magic_val   = ProtoField.string("des.magic",      "Magic Value")
des_protocol.fields.packet_cnt  = ProtoField.uint16("des.packet_cnt", "Packet Counter")
des_protocol.fields.dev_name    = ProtoField.string("des.dev_name",   "Device Name")
des_protocol.fields.dev_uptime  = ProtoField.string("des.dev_uptime", "Uptime")
des_protocol.fields.crc16_check = ProtoField.string("des.crc_check",  "Checksum")
des_protocol.fields.status      = ProtoField.string("des.status",     "Status")
des_protocol.fields.volume      = ProtoField.string("des.volume",     "Volume")

des_protocol.fields.todo_field1 = ProtoField.none("des.todo1", "Unknown Field")
des_protocol.fields.todo_field2 = ProtoField.none("des.todo2", "Unknown Field")
des_protocol.fields.todo_field3 = ProtoField.none("des.todo3", "Unknown Field")
des_protocol.fields.todo_field4 = ProtoField.none("des.todo4", "Unknown Field")
des_protocol.fields.todo_field5 = ProtoField.none("des.todo5", "Unknown Field")

output_channel = {}

for i = 0, 14, 1 do
   output_channel[i] = ProtoField.string(string.format("des.out%d", i), string.format("Output #%02d", i))
   table.insert(des_protocol.fields, output_channel[i])
end


function des_protocol.dissector(buffer, pinfo, tree)

   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = des_protocol.name

   local subtree = tree:add(des_protocol, buffer(), des_protocol.description)
   subtree:add(des_protocol.fields.magic_val,   buffer(0x0,2))
   subtree:add(des_protocol.fields.packet_cnt,  buffer(0x2,2))
   subtree:add(des_protocol.fields.todo_field1, buffer(0x4,15))
   subtree:add(des_protocol.fields.dev_name,    buffer(0x013,31))
   subtree:add(des_protocol.fields.todo_field2, buffer(0x32,2))

   for i = 0, 14, 1 do
      local out_val = string.format("%s [%s]", buffer(0x35+17*i, 16):string(), buffer(0x34+17*i, 1):uint() ~= 0x30 and "Enabled" or "Disabled")
      subtree:add(output_channel[i], buffer(0x34+17*i,17), out_val)
   end

   local function disp_status(stat)
      local power    = (bit32.band(stat, 0x8000) ~= 0) and "On" or "Standby"
      local muted    = (bit32.band(stat, 0x0002) ~= 0) and "Yes" or "No"
      local out_num  = bit32.rshift(bit32.band(stat, 0x003c), 2)
      local out_name = buffer(0x35+17*out_num, 16):string()
      return string.format("Power: %s, Output: %s, Muted: %s", power, out_name, muted)
   end

   subtree:add(des_protocol.fields.status, buffer(0x133,2), disp_status(buffer(0x133,2):uint()))

   subtree:add(des_protocol.fields.todo_field3, buffer(0x135,1))

   local vol = (buffer(0x136,1):uint() - 195) / 2.0
   subtree:add(des_protocol.fields.volume, buffer(0x136,1), string.format("%02.1f dB", vol))

   subtree:add(des_protocol.fields.todo_field4, buffer(0x137,20))

   local function disp_uptime(time)
      local days = math.floor(time / 86400000)
      local hours = math.floor((time % 86400000)/3600000)
      local minutes = math.floor((time % 3600000)/60000)
      local seconds = math.floor((time % 60000)/1000)
      local milli = math.floor(time % 1000)
      return string.format("%d days, %02d hours, %02d minutes, %02d sec, %03d ms", days, hours, minutes, seconds, milli)
   end

   subtree:add(des_protocol.fields.dev_uptime, buffer(0x014b,4), disp_uptime(buffer(0x014b,4):uint()))

   -- ccitt_16() taken from https://github.com/clarkli86/crc16_ccitt
   -- loop adjusted for wireshark Tvbrange as argument
   local function ccitt_16(byte_array)

      local POLY = 0x1021

      local function hash(crc, byte)
         for i = 0, 7 do
            local bit = bit32.extract(byte, 7 - i) -- Take the lsb
            local msb = bit32.extract(crc, 15, 1) -- msb
            crc = bit32.lshift(crc, 1) -- Remove the lsb of crc
            if bit32.bxor(bit, msb) == 1 then crc = bit32.bxor(crc, POLY) end
         end
         return crc
      end

      local crc = 0xffff
      for i = 0, byte_array:len()-1, 1 do
         crc = hash(crc, byte_array:range(i,1):uint())
      end

      return bit32.extract(crc, 0, 16)
   end

   subtree:add(des_protocol.fields.todo_field5, buffer(0x14f,8))

   local crc16_calc = ccitt_16(buffer(0x0,343))
   local crc16_read = buffer(0x157,2):uint()
   subtree:add(des_protocol.fields.crc16_check, buffer(0x157,2), crc16_calc == crc16_read and "Valid" or "Invalid")
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(45454, des_protocol)
