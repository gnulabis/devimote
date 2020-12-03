-- SPDX-FileCopyrightText: 2020 Dimitris Lampridis <dlampridis@gmail.com>
--
-- SPDX-License-Identifier: GPL-3.0-or-later

dec_protocol = Proto("DEC",  "Devialet Expert Control")

dec_protocol.fields.magic_val   = ProtoField.string("dec.magic",      "Magic Value")
dec_protocol.fields.packet_cnt  = ProtoField.uint16("dec.packet_cnt", "Packet Counter")
dec_protocol.fields.cmd_cnt     = ProtoField.uint16("dec.cmd_cnt",    "Command Counter")
dec_protocol.fields.cmd_type    = ProtoField.string("dec.cmd_type",   "Command")
dec_protocol.fields.out_sel     = ProtoField.uint16("dec.out_sel",    "Output Select")
dec_protocol.fields.volume      = ProtoField.uint16("dec.volume",     "Volume", base.HEX)
dec_protocol.fields.crc16_check = ProtoField.string("dec.crc_check",  "Checksum")

dec_protocol.fields.todo_field = ProtoField.none("dec.todo", "Unknown Field")
dec_protocol.fields.zero_field = ProtoField.none("dec.zero", "Zero Padding")

function dec_protocol.dissector(buffer, pinfo, tree)

   length = buffer:len()
   if length == 0 then return end

   pinfo.cols.protocol = dec_protocol.name

   local subtree = tree:add(dec_protocol, buffer(), dec_protocol.description)
   subtree:add(dec_protocol.fields.magic_val,   buffer(0x0,2))
   subtree:add(dec_protocol.fields.packet_cnt,  buffer(0x2,2))
   subtree:add(dec_protocol.fields.cmd_cnt,     buffer(0x4,2))

   local opstring = "UNKNOWN"
   local opcode = buffer(0x6,2):uint()

   if     (opcode == 0x0004) then opstring = "VOLUME"
   elseif (opcode == 0x0005) then opstring = "OUTPUT"
   elseif (opcode == 0x0001) then opstring = "STANDBY"
   elseif (opcode == 0x0101) then opstring = "ON"
   elseif (opcode == 0x0107) then opstring = "MUTE"
   elseif (opcode == 0x0007) then opstring = "UNMUTE"
   end

   subtree:add(dec_protocol.fields.cmd_type, buffer(0x6,2), opstring)

   if (opstring == "VOLUME") then
      local volume = buffer(0x8,2):uint()
      subtree:add(dec_protocol.fields.volume, volume)
      subtree:add(dec_protocol.fields.zero_field, buffer(0xa,2))
      pinfo.cols.info:append(string.format(" Cmd=%s %x", opstring, volume))
   elseif (opstring == "OUTPUT SELECT") then
      local out_sel = bit32.band(buffer(0x8,2):uint(), 0x01ff)
      if (bit32.band(out_sel, 0x100) ~= 0) then
         out_sel = bit32.band(out_sel, 0xff)
         out_sel = bit32.lshift(out_sel, 1)
         out_sel = bit32.bor(out_sel, 0x100)
      end
      out_sel = bit32.rshift(out_sel, 5)
      subtree:add(dec_protocol.fields.out_sel, buffer(0x8,2), out_sel)
      subtree:add(dec_protocol.fields.zero_field, buffer(0xa,2))
      pinfo.cols.info:append(string.format(" Cmd=%s #%02d", opstring, out_sel))
   else
      subtree:add(dec_protocol.fields.zero_field, buffer(0x8,4))
      pinfo.cols.info:append(string.format(" Cmd=%s", opstring))
   end

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

   local crc16_calc = ccitt_16(buffer(0x0,12))
   local crc16_read = buffer(0xc,2):uint()
   subtree:add(dec_protocol.fields.crc16_check, buffer(0xc,2), crc16_calc == crc16_read and "Valid" or "Invalid")
   -- local crc16_calc = ccitt_16(buffer(0xe,126))
   -- local crc16_read = buffer(0x8c,2):uint()
   -- subtree:add(dec_protocol.fields.crc16_data, buffer(0xe,126), crc16_calc == crc16_read and "Valid" or "Invalid")

   subtree:add(dec_protocol.fields.todo_field, buffer(0xe,128))

end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(45455, dec_protocol)
