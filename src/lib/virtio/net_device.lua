-- Implements virtio-net device


module(...,package.seeall)

local buffer    = require("core.buffer")
local freelist  = require("core.freelist")
local lib       = require("core.lib")
local link      = require("core.link")
local memory    = require("core.memory")
local packet    = require("core.packet")
local timer     = require("core.timer")
local tlb       = require("lib.tlb")
local vq        = require("lib.virtio.virtq")
local ffi       = require("ffi")
local C         = ffi.C
local band      = bit.band
local get_buffers = vq.VirtioVirtq.get_buffers

require("lib.virtio.virtio.h")
require("lib.virtio.virtio_vring_h")

local char_ptr_t = ffi.typeof("char *")
local virtio_net_hdr_size = ffi.sizeof("struct virtio_net_hdr")
local virtio_net_hdr_mrg_rxbuf_size = ffi.sizeof("struct virtio_net_hdr_mrg_rxbuf")
local virtio_net_hdr_mrg_rxbuf_type = ffi.typeof("struct virtio_net_hdr_mrg_rxbuf *")
local packet_info_size = ffi.sizeof("struct packet_info")
local buffer_t = ffi.typeof("struct buffer")

local invalid_header_id = 0xffff

--[[
   A list of what needs to be implemented in order to fully support
   some of the options.

   - VIRTIO_NET_F_CSUM - enables the SG I/O (resulting in
      multiple chained data buffers in our TX path(self.rxring))
      Required by GSO/TSO/USO. Requires CSUM offload support in the
      HW driver (now intel10g)

   - VIRTIO_NET_F_MRG_RXBUF - enables multiple chained buffers in our RX path
      (self.txring). Also chnages the virtio_net_hdr to virtio_net_hdr_mrg_rxbuf

   - VIRTIO_F_ANY_LAYOUT - the virtio_net_hdr/virtio_net_hdr_mrg_rxbuf is "prepended"
      in the first data buffer instead if provided by a separate descriptor.
      Supported in fairly recent (3.13) Linux kernels

   - VIRTIO_RING_F_INDIRECT_DESC - support indirect buffer descriptors.

   - VIRTIO_NET_F_CTRL_VQ - creates a separate control virt queue

   - VIRTIO_NET_F_MQ - multiple RX/TX queues, usefull for SMP (host/guest).
      Requires VIRTIO_NET_F_CTRL_VQ

--]]
local supported_features = C.VIRTIO_F_ANY_LAYOUT +
                           C.VIRTIO_RING_F_INDIRECT_DESC +
                           C.VIRTIO_NET_F_CTRL_VQ +
                           C.VIRTIO_NET_F_MQ +
                           C.VIRTIO_NET_F_MRG_RXBUF
--[[
   The following offloading flags are also available:
   VIRTIO_NET_F_CSUM
   VIRTIO_NET_F_GUEST_CSUM
   VIRTIO_NET_F_GUEST_TSO4 + VIRTIO_NET_F_GUEST_TSO6 + VIRTIO_NET_F_GUEST_ECN + VIRTIO_NET_F_GUEST_UFO
   VIRTIO_NET_F_HOST_TSO4 + VIRTIO_NET_F_HOST_TSO6 + VIRTIO_NET_F_HOST_ECN + VIRTIO_NET_F_HOST_UFO
]]--

local max_virtq_pairs = 16

VirtioNetDevice = {}

function VirtioNetDevice:new(owner)
   assert(owner)
   local o = {
      owner = owner,
      callfd = {},
      kickfd = {},
      virtq = {},
      rx = {},
      tx = {},
      -- buffer records that are not currently in use
      buffer_recs = freelist.new("struct buffer *", 32*1024),
      -- buffer records populated with available VM memory
      vring_transmit_buffers = freelist.new("struct buffer *", 32*1024),
   }

   o = setmetatable(o, {__index = VirtioNetDevice})

   for i = 0, max_virtq_pairs-1 do
      -- TXQ
      o.virtq[2*i] = vq.VirtioVirtq:new()
      o.virtq[2*i].device = o
      -- RXQ
      o.virtq[2*i+1] = vq.VirtioVirtq:new()
      o.virtq[2*i+1].device = o
   end

   self.virtq_pairs = 1
   self.hdr_size = virtio_net_hdr_size

   return o
end

function VirtioNetDevice:poll_vring_receive ()
   -- RX
   self:receive_packets_from_vm()
   self:rx_signal_used()
end

function VirtioNetDevice:poll_vring_transmit ()
   -- TX
   self:get_transmit_buffers_from_vm()
   self:transmit_packets_to_vm()
end

function VirtioNetDevice:rx_packet_start(header_id, addr, len)
   local rx_p = packet.allocate()
   local header_id = header_id
   local header_pointer = ffi.cast(char_ptr_t,self:map_from_guest(addr))
   local total_size = self.hdr_size
   local header_len = self.hdr_size

   return header_id, header_pointer, total_size, header_len, rx_p
end

function VirtioNetDevice:rx_buffer_add(rx_p, addr, len, rx_total_size, tx)
   local buf = freelist.remove(self.buffer_recs) or lib.malloc(buffer_t)

   local addr = self:map_from_guest(addr)
   buf.pointer = ffi.cast(char_ptr_t, addr)
   buf.physical = self:translate_physical_addr(addr)
   buf.size = len

   -- Fill buffer origin info
   buf.origin.type = C.BUFFER_ORIGIN_VIRTIO
   -- Set invalid header_id for all buffers. The first will contain
   -- the real header_id, set after the loop
   buf.origin.info.virtio.header_id = invalid_header_id

   packet.add_iovec(rx_p, buf, buf.size)

   -- The total size will be added to the first buffer virtio info
   local new_total_size = rx_total_size + buf.size

   return nil, new_total_size
end

function VirtioNetDevice:rx_packet_end(rx_header_id, rx_header_pointer, rx_total_size, rx_p, buf)
   -- Fill in the first buffer with header info
   local v = rx_p.iovecs[0].buffer.origin.info.virtio
   v.device_id      = self.virtio_device_id
   v.ring_id        = self.ring_id
   v.header_id      = rx_header_id
   v.header_pointer = rx_header_pointer
   v.total_size     = rx_total_size
   ffi.copy(rx_p.info, rx_header_pointer, packet_info_size)

   local l = self.owner.output.tx
   if l then
      link.transmit(l, rx_p)
   else
      debug("droprx", "len", rx_p.length, "niovecs", rx_p.niovecs)
      packet.deref(rx_p)
   end
end

-- Receive all available packets from the virtual machine.
function VirtioNetDevice:receive_packets_from_vm ()
   for i = 0, self.virtq_pairs-1 do
      self.ring_id = 2*i+1
      local virtq = self.virtq[self.ring_id]
      local ops = {
         packet_start = self.rx_packet_start,
         buffer_add   = self.rx_buffer_add,
         packet_end   = self.rx_packet_end
      }
      get_buffers(virtq, 'rx', ops)
   end
end

function VirtioNetDevice:tx_packet_start(header_id, addr, len)
   local tx_header_pointer = ffi.cast(char_ptr_t, self:map_from_guest(addr))
   return header_id, tx_header_pointer, self.hdr_size, self.hdr_size, nil
end

function VirtioNetDevice:tx_buffer_add(tx_p, addr, len, tx_total_size, tx)
   local buf = freelist.remove(self.buffer_recs) or lib.malloc(buffer_t)

   local addr = self:map_from_guest(addr)
   buf.pointer = ffi.cast(char_ptr_t, addr)
   buf.physical = self:translate_physical_addr(addr)
   buf.size = len

   -- Fill buffer origin info
   buf.origin.type = C.BUFFER_ORIGIN_VIRTIO

   local new_total_size = tx_total_size + buf.size
   -- TODO: supports single buffer now!
   return buf, new_total_size
end

function VirtioNetDevice:tx_packet_end(tx_header_id, tx_header_pointer,
   tx_total_size, _p, buf)
   -- TODO: supports single buffer now!
   local v = buf.origin.info.virtio
   v.device_id      = self.virtio_device_id
   v.ring_id        = self.ring_id
   v.header_id      = tx_header_id
   v.header_pointer = tx_header_pointer
   v.total_size     = tx_total_size

   freelist.add(self.vring_transmit_buffers, buf)
end

-- Populate the `self.vring_transmit_buffers` freelist with buffers from the VM.
function VirtioNetDevice:get_transmit_buffers_from_vm ()
   for i = 0, self.virtq_pairs-1 do
      self.ring_id = 2*i
      local virtq = self.virtq[self.ring_id]
      local ops = {
         packet_start = self.tx_packet_start,
         buffer_add   = self.tx_buffer_add,
         packet_end   = self.tx_packet_end
      }
      get_buffers(virtq, 'tx', ops)
   end
end

function VirtioNetDevice:more_vm_buffers ()
   return freelist.nfree(self.vring_transmit_buffers) > 2
end

-- return the buffer from a iovec, ensuring it originates from the vm
local last_size = nil
function VirtioNetDevice:vm_buffer (iovec)
   local should_continue = true
   local b = iovec.buffer
   -- check if this is a zero-copy packet
   if b.origin.type ~= C.BUFFER_ORIGIN_VIRTIO then
      -- get buffer from the once supplied by the VM
      local old_b = b
      b = freelist.remove(self.vring_transmit_buffers)
      --assert(iovec.offset + iovec.length <= b.size)

      -- copy the whole buffer data, including offset
      ffi.copy(b.pointer, old_b.pointer, iovec.offset + iovec.length)
      buffer.free(old_b)
      iovec.buffer = b

      if not self:more_vm_buffers() then
         -- no more buffers, stop the loop
         should_continue = false
      end
   else
      if iovec.offset ~= 0 then
         -- Virtio requires the offset to be 0. Move the memory to make it so.
         C.memmove(b.pointer, b.pointer + iovec.offset, iovec.length)
         iovec.offset = 0
      end
   end
   if last_size ~= b.size then print("size=", b.size) last_size=b.size end
   return should_continue, b
end

-- Transmit packets from the app input queue to the VM.
function VirtioNetDevice:transmit_packets_to_vm ()
   local l = self.owner.input.rx
   if not l then return end
   local should_continue = not self.not_enough_vm_bufers

   while (not link.empty(l)) and should_continue do
      local p = link.receive(l)

      if p.niovecs > 1 then
         assert(self.mrg_rxbuf)
      end

      -- Iterate over all iovecs
      for i = 0, p.niovecs - 1 do

         local iovec = p.iovecs[i]
         local should_continue, b = self:vm_buffer(iovec)
         local size = iovec.length

         -- fill in the virtio header
         if b then
            local v = b.origin.info.virtio
            local virtio_hdr = v.header_pointer
            -- the first buffer always contains the header
            if i == 0 then
               ffi.copy(virtio_hdr, p.info, packet_info_size)
               size = size + self.hdr_size
               -- when using mergeable buffers, set the num_buffers field
               if self.mrg_rxbuf then
                  local hdr = ffi.cast(virtio_net_hdr_mrg_rxbuf_type, virtio_hdr)
                  hdr.num_buffers = p.niovecs
               end
            else
               -- the other buffer need to left shift the data over the header
               -- here we assume that the header precedes the buffer
               -- which is the common case when mergeable buffers are used

               --assert(virto_hdr+virtio_net_hdr_mrg_rxbuf_size == b.pointer)
               C.memmove(virtio_hdr, b.pointer, iovec.length)
            end

            self.virtq[v.ring_id]:put_buffer(v.header_id, size)
         end
         if not should_continue then break end
      end

      packet.deref(p)
   end

   if not should_continue then
      -- not enough buffers detected, verify once again
      self.not_enough_vm_bufers = not self:more_vm_buffers()
   end

   for i = 0, self.virtq_pairs-1 do
      self.virtq[2*i]:signal_used()
   end
end

-- Return a buffer to the virtual machine.
function VirtioNetDevice:return_virtio_buffer (b)
   freelist.add(self.buffer_recs, b)
   if b.origin.info.virtio.ring_id == 1 then -- Receive buffer?

      -- Only do this for the first buffer in the chain.
      -- Distiguish it by the valid header_id
      -- Other buffers in the chain are safe as long as
      -- rx_signal_used() is not called. So be sure to free
      -- all of them at one poll.
      if b.origin.info.virtio.header_id ~= invalid_header_id then
         self.virtq[b.origin.info.virtio.ring_id]:put_buffer(b.origin.info.virtio.header_id, b.origin.info.virtio.total_size)
      end
   end
end

-- Advance the rx used ring and signal up
function VirtioNetDevice:rx_signal_used()
   for i = 0, self.virtq_pairs-1 do
      self.virtq[2*i+1]:signal_used()
   end
end

local pagebits = memory.huge_page_bits

-- Cache of the latest referenced physical page.
function VirtioNetDevice:translate_physical_addr (addr)
   local page = bit.rshift(addr, pagebits)
   if page == self.last_virt_page then
      return addr + self.last_virt_offset
   end
   local phys = memory.virtual_to_physical(addr)
   self.last_virt_page = page
   self.last_virt_offset = phys - addr
   return phys
end

function VirtioNetDevice:map_from_guest (addr)
   local page = bit.rshift(addr, pagebits)
   if page == self.last_guest_page then return addr + self.last_guest_offset end
   local result
   for i = 0, table.getn(self.mem_table) do
      local m = self.mem_table[i]
      if addr >= m.guest and addr < m.guest + m.size then
         if i ~= 0 then
            self.mem_table[i] = self.mem_table[0]
            self.mem_table[0] = m
         end
         result = addr + m.snabb - m.guest
         self.last_guest_page = page
         self.last_guest_offset = m.snabb - m.guest
         break
      end
   end
   if not result then
      error("mapping to host address failed" .. tostring(ffi.cast("void*",addr)))
   end
   return result
end

function VirtioNetDevice:map_from_qemu (addr)
   local result = nil
   for i = 0, table.getn(self.mem_table) do
      local m = self.mem_table[i]
      if addr >= m.qemu and addr < m.qemu + m.size then
         result = addr + m.snabb - m.qemu
         break
      end
   end
   if not result then
      error("mapping to host address failed" .. tostring(ffi.cast("void*",addr)))
   end
   return result
end

function VirtioNetDevice:get_features()
   print(string.format("Get features 0x%x\n%s", tonumber(supported_features), get_feature_names(supported_features)))
   return supported_features
end

function VirtioNetDevice:set_features(features)
   print(string.format("Set features 0x%x\n%s", tonumber(features), get_feature_names(features)))
   self.features = features
   if band(self.features, C.VIRTIO_NET_F_MRG_RXBUF) == C.VIRTIO_NET_F_MRG_RXBUF then
      self.hdr_size = virtio_net_hdr_mrg_rxbuf_size
      self.mrg_rxbuf = true
   end
end

function VirtioNetDevice:set_vring_num(idx, num)
   local n = tonumber(num)
   if band(n, n - 1) ~= 0 then
      error("vring_num should be power of 2")
   end

   self.virtq[idx].vring_num = n
   -- update the curent virtq pairs
   self.virtq_pairs = math.max(self.virtq_pairs, math.floor(idx/2)+1)
end

function VirtioNetDevice:set_vring_call(idx, fd)
   self.virtq[idx].callfd = fd
end

function VirtioNetDevice:set_vring_kick(idx, fd)
   self.virtq[idx].kickfd = fd
end

function VirtioNetDevice:set_vring_addr(idx, ring)

   self.virtq[idx].virtq = ring
   self.virtq[idx].avail = tonumber(ring.used.idx)
   self.virtq[idx].used = tonumber(ring.used.idx)
   print(string.format("rxavail = %d rxused = %d", self.virtq[idx].avail, self.virtq[idx].used))
   ring.used.flags = C.VRING_F_NO_NOTIFY
end

function VirtioNetDevice:ready()
   return self.virtq[0].virtq and self.virtq[1].virtq
end

function VirtioNetDevice:set_vring_base(idx, num)
   self.virtq[idx].avail = num
end

function VirtioNetDevice:get_vring_base(idx)
   return self.virtq[idx].avail
end

function VirtioNetDevice:set_mem_table(mem_table)
   self.mem_table = mem_table
end

function VirtioNetDevice:report()
   debug("txavail", self.virtq[0].virtq.avail.idx,
      "txused", self.virtq[0].virtq.used.idx,
      "rxavail", self.virtq[1].virtq.avail.idx,
      "rxused", self.virtq[1].virtq.used.idx)
end

function VirtioNetDevice:rx_buffers()
   return self.vring_transmit_buffers
end

function VirtioNetDevice:set_virtio_device_id(virtio_device_id)
   self.virtio_device_id = virtio_device_id
end

feature_names = {
   [C.VIRTIO_F_NOTIFY_ON_EMPTY]                 = "VIRTIO_F_NOTIFY_ON_EMPTY",
   [C.VIRTIO_RING_F_INDIRECT_DESC]              = "VIRTIO_RING_F_INDIRECT_DESC",
   [C.VIRTIO_RING_F_EVENT_IDX]                  = "VIRTIO_RING_F_EVENT_IDX",

   [C.VIRTIO_F_ANY_LAYOUT]                      = "VIRTIO_F_ANY_LAYOUT",
   [C.VIRTIO_NET_F_CSUM]                        = "VIRTIO_NET_F_CSUM",
   [C.VIRTIO_NET_F_GUEST_CSUM]                  = "VIRTIO_NET_F_GUEST_CSUM",
   [C.VIRTIO_NET_F_GSO]                         = "VIRTIO_NET_F_GSO",
   [C.VIRTIO_NET_F_GUEST_TSO4]                  = "VIRTIO_NET_F_GUEST_TSO4",
   [C.VIRTIO_NET_F_GUEST_TSO6]                  = "VIRTIO_NET_F_GUEST_TSO6",
   [C.VIRTIO_NET_F_GUEST_ECN]                   = "VIRTIO_NET_F_GUEST_ECN",
   [C.VIRTIO_NET_F_GUEST_UFO]                   = "VIRTIO_NET_F_GUEST_UFO",
   [C.VIRTIO_NET_F_HOST_TSO4]                   = "VIRTIO_NET_F_HOST_TSO4",
   [C.VIRTIO_NET_F_HOST_TSO6]                   = "VIRTIO_NET_F_HOST_TSO6",
   [C.VIRTIO_NET_F_HOST_ECN]                    = "VIRTIO_NET_F_HOST_ECN",
   [C.VIRTIO_NET_F_HOST_UFO]                    = "VIRTIO_NET_F_HOST_UFO",
   [C.VIRTIO_NET_F_MRG_RXBUF]                   = "VIRTIO_NET_F_MRG_RXBUF",
   [C.VIRTIO_NET_F_STATUS]                      = "VIRTIO_NET_F_STATUS",
   [C.VIRTIO_NET_F_CTRL_VQ]                     = "VIRTIO_NET_F_CTRL_VQ",
   [C.VIRTIO_NET_F_CTRL_RX]                     = "VIRTIO_NET_F_CTRL_RX",
   [C.VIRTIO_NET_F_CTRL_VLAN]                   = "VIRTIO_NET_F_CTRL_VLAN",
   [C.VIRTIO_NET_F_CTRL_RX_EXTRA]               = "VIRTIO_NET_F_CTRL_RX_EXTRA",
   [C.VIRTIO_NET_F_CTRL_MAC_ADDR]               = "VIRTIO_NET_F_CTRL_MAC_ADDR",
   [C.VIRTIO_NET_F_CTRL_GUEST_OFFLOADS]         = "VIRTIO_NET_F_CTRL_GUEST_OFFLOADS",

   [C.VIRTIO_NET_F_MQ]                          = "VIRTIO_NET_F_MQ"
}

function get_feature_names(bits)
local string = ""
   for mask,name in pairs(feature_names) do
      if (bit.band(bits,mask) == mask) then
         string = string .. " " .. name
      end
   end
   return string
end

function debug (...)
   print(...)
end
