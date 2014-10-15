module(...,package.seeall)

local zone = require("jit.zone")
local basic_apps = require("apps.basic.basic_apps")
local lib      = require("core.lib")
local register = require("lib.hardware.register")
local intel10g = require("apps.intel.intel10g")
local freelist = require("core.freelist")
local receive, transmit, full, empty = link.receive, link.transmit, link.full, link.empty
Intel82599 = {}
Intel82599.__index = Intel82599

-- table pciaddr => {pf, vflist}
local devices = {}


local function firsthole(t)
   for i = 1, #t+1 do
      if t[i] == nil then
         return i
      end
   end
end


-- Create an Intel82599 App for the device with 'pciaddress'.
function Intel82599:new (args)
   args = config.parse_app_arg(args)

   if args.vmdq then
      if devices[args.pciaddr] == nil then
         devices[args.pciaddr] = {pf=intel10g.new_pf(args.pciaddr):open(), vflist={}}
      end
      local dev = devices[args.pciaddr]
      local poolnum = firsthole(dev.vflist)-1
      local vf = dev.pf:new_vf(poolnum)
      dev.vflist[poolnum+1] = vf
      return setmetatable({dev=vf:open(args)}, Intel82599)
   else
      local dev = intel10g.new_sf(args.pciaddr)
         :open()
         :autonegotiate_sfi()
         :wait_linkup()
      if not dev then return null end
      return setmetatable({dev=dev, zone="intel"}, Intel82599)
   end
end

function Intel82599:stop()
   local close_pf = nil
   if self.dev.pf and devices[self.dev.pf.pciaddress] then
      local poolnum = self.dev.poolnum
      local pciaddress = self.dev.pf.pciaddress
      local dev = devices[pciaddress]
      if dev.vflist[poolnum+1] == self.dev then
         dev.vflist[poolnum+1] = nil
      end
      if next(dev.vflist) == nil then
         close_pf = devices[pciaddress].pf
         devices[pciaddress] = nil
      end
   end
   self.dev:close()
   if close_pf then
      close_pf:close()
   end
end

-- Allocate receive buffers from the given freelist.
function Intel82599:set_rx_buffer_freelist (fl)
   self.rx_buffer_freelist = fl
end

-- Pull in packets from the network and queue them on our 'tx' link.
function Intel82599:pull ()
   local l = self.output.tx
   if l == nil then return end
   self.dev:sync_receive()
   while not full(l) and self.dev:can_receive() do
      transmit(l, self.dev:receive())
   end
   self:add_receive_buffers()
end

function Intel82599:add_receive_buffers ()
   if self.rx_buffer_freelist == nil then
      -- Generic buffers
      while self.dev:can_add_receive_buffer() do
         self.dev:add_receive_buffer(buffer.allocate())
      end
   else
      -- Buffers from a special freelist
      local fl = self.rx_buffer_freelist
      while self.dev:can_add_receive_buffer() and freelist.nfree(fl) > 0 do
         local b = freelist.remove(fl)
         if b.size < 1024 then
            buffer.free(b)
            b = buffer.allocate()
         end
         self.dev:add_receive_buffer(b)
      end
   end
end

-- Push packets from our 'rx' link onto the network.
function Intel82599:push ()
   local l = self.input.rx
   if l == nil then return end
   while not empty(l) and self.dev:can_transmit() do
      do local p = receive(l)
	 self.dev:transmit(p)
	 packet.deref(p)
      end
   end
   self.dev:sync_transmit()
end

-- Report on relevant status and statistics.
function Intel82599:report ()
   print("report on intel device", self.dev.pciaddress or self.dev.pf.pciaddress)
   --register.dump(self.dev.r)
   register.dump(self.dev.s, true)
   if self.dev.rxstats then
      for name,v in pairs(self.dev:get_rxstats()) do
         io.write(string.format('%30s: %d\n', 'rx '..name, v))
      end
   end
   if self.dev.txstats then
      for name,v in pairs(self.dev:get_txstats()) do
         io.write(string.format('%30s: %d\n', 'tx '..name, v))
      end
   end
   register.dump({
      self.dev.r.TDH, self.dev.r.TDT,
      self.dev.r.RDH, self.dev.r.RDT,
      self.dev.r.AUTOC or self.dev.pf.r.AUTOC,
      self.dev.r.AUTOC2 or self.dev.pf.r.AUTOC2,
      self.dev.r.LINKS or self.dev.pf.r.LINKS,
      self.dev.r.LINKS2 or self.dev.pf.r.LINKS2,
   })
end

function selftest ()
   print("selftest: intel_app")

   local pcideva = os.getenv("SNABB_TEST_INTEL10G_PCIDEVA")
   local pcidevb = os.getenv("SNABB_TEST_INTEL10G_PCIDEVB")
   if not pcideva or not pcidevb then
      print("SNABB_TEST_INTEL10G_[PCIDEVA | PCIDEVB] was not set\nTest skipped")
      os.exit(engine.test_skipped_code)
   end

   zone('buffer') buffer.preallocate(100000) zone()

   mq_sw(pcideva)
   engine.main({duration = 1, report={showlinks=true, showapps=false}})
   do
      local a0Sends = engine.app_table.nicAm0.input.rx.stats.txpackets
      local a1Gets = engine.app_table.nicAm1.output.tx.stats.rxpackets
      if a1Gets < a0Sends/4
         or a1Gets > a0Sends*3/4
      then
         print ('wrong proportion of packets passed/discarded')
         os.exit(1)
      end
   end

   sq_sq(pcideva, pcidevb)
   engine.main({duration = 1, report={showlinks=true, showapps=false}})

   do
      local aSends = engine.app_table.nicA.input.rx.stats.txpackets
      local aGets = engine.app_table.nicA.output.tx.stats.rxpackets
      local bSends = engine.app_table.nicB.input.rx.stats.txpackets
      local bGets = engine.app_table.nicB.output.tx.stats.rxpackets

      if bGets < aSends/2
         or aGets < bSends/2
         or bGets < aGets/2
         or aGets < bGets/2
      then
         print ('not enought packets somewhere')
         os.exit (1)
      end
   end

   mq_sq(pcideva, pcidevb)
   engine.main({duration = 1, report={showlinks=true, showapps=false}})

   do
      local aSends = engine.app_table.nicAs.input.rx.stats.txpackets
      local b0Gets = engine.app_table.nicBm0.output.tx.stats.rxpackets
      local b1Gets = engine.app_table.nicBm1.output.tx.stats.rxpackets

      if b0Gets < b1Gets/2 or
         b1Gets < b0Gets/2 or
         b0Gets+b1Gets < aSends/2
      then
         print ('not enought packets somewhere')
         os.exit (1)
      end
   end
end

-- open two singlequeue drivers on both ends of the wire
function sq_sq(pcidevA, pcidevB)
   engine.configure(config.new())
   local c = config.new()
   print ('-------')
   print ('just send a lot of packets through the wire')
   config.app(c, 'source1', basic_apps.Source)
   config.app(c, 'source2', basic_apps.Source)
   config.app(c, 'nicA', Intel82599, ([[{pciaddr='%s'}]]):format(pcidevA))
   config.app(c, 'nicB', Intel82599, ([[{pciaddr='%s'}]]):format(pcidevB))
   config.app(c, 'sink', basic_apps.Sink)
   config.link(c, 'source1.out -> nicA.rx')
   config.link(c, 'source2.out -> nicB.rx')
   config.link(c, 'nicA.tx -> sink.in1')
   config.link(c, 'nicB.tx -> sink.in2')
   engine.configure(c)
end

-- one singlequeue driver and a multiqueue at the other end
function mq_sq(pcidevA, pcidevB)
   local d1 = lib.hexundump ([[
      52:54:00:02:02:02 52:54:00:01:01:01 08 00 45 00
      00 54 c3 cd 40 00 40 01 f3 23 c0 a8 01 66 c0 a8
      01 01 08 00 57 ea 61 1a 00 06 5c ba 16 53 00 00
      00 00 04 15 09 00 00 00 00 00 10 11 12 13 14 15
      16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
      26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
      36 37
   ]], 98)                  -- src: As    dst: Bm0
   local d2 = lib.hexundump ([[
      52:54:00:03:03:03 52:54:00:01:01:01 08 00 45 00
      00 54 c3 cd 40 00 40 01 f3 23 c0 a8 01 66 c0 a8
      01 01 08 00 57 ea 61 1a 00 06 5c ba 16 53 00 00
      00 00 04 15 09 00 00 00 00 00 10 11 12 13 14 15
      16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
      26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
      36 37
   ]], 98)                  -- src: As    dst: Bm1
   engine.configure(config.new())
   local c = config.new()
   config.app(c, 'source_ms', basic_apps.Join)
   config.app(c, 'repeater_ms', basic_apps.Repeater)
   config.app(c, 'nicAs', Intel82599, ([[{
   -- Single App on NIC A
      pciaddr = '%s',
      macaddr = '52:54:00:01:01:01',
   }]]):format(pcidevA))
   config.app(c, 'nicBm0', Intel82599, ([[{
   -- first VF on NIC B
      pciaddr = '%s',
      vmdq = true,
      macaddr = '52:54:00:02:02:02',
   }]]):format(pcidevB))
   config.app(c, 'nicBm1', Intel82599, ([[{
   -- second VF on NIC B
      pciaddr = '%s',
      vmdq = true,
      macaddr = '52:54:00:03:03:03',
   }]]):format(pcidevB))
   print ('-------')
   print ("Send a bunch of from the SF on NIC A to the VFs on NIC B")
   print ("half of them go to nicBm0 and nicBm0")
   config.app(c, 'sink_ms', basic_apps.Sink)
   config.link(c, 'source_ms.out -> repeater_ms.input')
   config.link(c, 'repeater_ms.output -> nicAs.rx')
   config.link(c, 'nicAs.tx -> sink_ms.in1')
   config.link(c, 'nicBm0.tx -> sink_ms.in2')
   config.link(c, 'nicBm1.tx -> sink_ms.in3')
   engine.configure(c)
   link.transmit(engine.app_table.source_ms.output.out, packet.from_data(d1))
   link.transmit(engine.app_table.source_ms.output.out, packet.from_data(d2))
end

-- one multiqueue driver with two apps and do switch stuff
function mq_sw(pcidevA)
   local d1 = lib.hexundump ([[
      52:54:00:02:02:02 52:54:00:01:01:01 08 00 45 00
      00 54 c3 cd 40 00 40 01 f3 23 c0 a8 01 66 c0 a8
      01 01 08 00 57 ea 61 1a 00 06 5c ba 16 53 00 00
      00 00 04 15 09 00 00 00 00 00 10 11 12 13 14 15
      16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
      26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
      36 37
   ]], 98)                  -- src: Am0    dst: Am1
   local d2 = lib.hexundump ([[
      52:54:00:03:03:03 52:54:00:01:01:01 08 00 45 00
      00 54 c3 cd 40 00 40 01 f3 23 c0 a8 01 66 c0 a8
      01 01 08 00 57 ea 61 1a 00 06 5c ba 16 53 00 00
      00 00 04 15 09 00 00 00 00 00 10 11 12 13 14 15
      16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25
      26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35
      36 37
   ]], 98)                  -- src: Am0    dst: ---
   engine.configure(config.new())
   local c = config.new()
   config.app(c, 'source_ms', basic_apps.Join)
   config.app(c, 'repeater_ms', basic_apps.Repeater)
   config.app(c, 'nicAm0', Intel82599, ([[{
   -- first VF on NIC A
      pciaddr = '%s',
      vmdq = true,
      macaddr = '52:54:00:01:01:01',
   }]]):format(pcidevA))
   config.app(c, 'nicAm1', Intel82599, ([[{
   -- second VF on NIC A
      pciaddr = '%s',
      vmdq = true,
      macaddr = '52:54:00:02:02:02',
   }]]):format(pcidevA))
   print ('-------')
   print ("Send a bunch of packets from Am0")
   print ("half of them go to nicAm1 and half go nowhere")
   config.app(c, 'sink_ms', basic_apps.Sink)
   config.link(c, 'source_ms.out -> repeater_ms.input')
   config.link(c, 'repeater_ms.output -> nicAm0.rx')
   config.link(c, 'nicAm0.tx -> sink_ms.in1')
   config.link(c, 'nicAm1.tx -> sink_ms.in2')
   engine.configure(c)
   link.transmit(engine.app_table.source_ms.output.out, packet.from_data(d1))
   link.transmit(engine.app_table.source_ms.output.out, packet.from_data(d2))
end
