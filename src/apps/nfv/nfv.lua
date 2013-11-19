module(...,package.seeall)

NFV = {}

-- Network Functions Virtualization application.
--
-- This is designed to provide efficient ethernet I/O to virtual
-- machines based on zero-copy DMA between network and guest.
--
-- The intended benefits compared with SR-IOV with PCI-Passthrough are:
--
--   Hardware independent. The guest VM sees a standard Virtio-net
--   device and is not exposed to the underlying physical hardware.
--
--   Programmable. Packet forwarding/filtering/ACL logic can be
--   inserted as software and is not restricted to the hardware
--   switching capabilities of the NIC.
--
-- The cost is that the CPU performs DMA address translation and
-- converts TX/RX descriptors between virtio and native hardware
-- formats. Hopefully this will be cheap.

function NFV:new (virtio, nic)
   nfv = {
      virtio = virtio, -- Virtio-net vhost device
      nic = nic        -- Physical NIC
   }
   setmetatable(nfv, {__index = NFV})
   return nfv
end

function NFV:pull ()
   local virtio, nic = self.virtio, self.nic
   -- Give virtio RX buffers to the NIC.
   while virtio:has_receive_buffer() and nic:can_add_receive_buffer() do
      local b = virtio:get_receive_buffer()
      map_dma(b, 'vm->nic')
      nic:add_receive_buffer(b)
   end
   -- Take used TX buffers from the NIC and give them back to virtio.
   while nic:can_reclaim_transmit_buffer() do
      local b = nic:reclaim_transmit_buffer()
      map_dma(b, 'nic->vm')
      virtio:return_transmit_buffer(b)
   end
   -- Pass received packets to Virtio.
   while nic:can_receive() and virtio:can_transmit() do
      local p = nic:receive()
      for i = 0, p.noivecs-1 do
	 map_dma(p.iovecs[i].buffer, 'nic->vm')
      end
      virtio:transmit(p)
   end
   -- Pass transmit-ready packets to the NIC.
   while nic:can_transmit() and virtio:can_receive() do
      local p = virtio:receive()
      for i = 0, p.noivecs-1 do
	 map_dma(p.iovecs[i].buffer, 'vm->nic')
      end
      nic:transmit(p)
   end
end

-- DMA address translation table.
-- This should be dynamically populated from the Virtio device.
dma_map = { { start = 0x10000, finish = 0x20000, offset = 0xA00000 },
	    { start = 0x40000, finish = 0x50000, offset = 0xC00000 } }

-- Software IOMMU mapping between VM and NIC address spaces.
-- (Maybe this should be dynamically compiled as LuaJIT code?)
function map_dma (b, direction)
   local sign = { 'vm->nic' = 1, 'nic->vm' = -1 }
   local addr = b.physical
   for m in ipairs(dma_map) do
      if addr >= m.start and addr <= m.finish then
	 b.physical = b.physical + m.offset * sign[direction]
	 return
      end
   end
   error(("%s DMA mapping failed for address %x"):format(direction, addr))
end

