module(...,package.seeall)

local Intel82599 = require("apps.intel.intel_app").Intel82599
local VhostUser = require("apps.vhost.vhost_user").VhostUser
local PacketFilter = require("apps.packet_filter.packet_filter").PacketFilter
local RateLimiter = require("apps.rate_limiter.rate_limiter").RateLimiter
local nd_light = require("apps.ipv6.nd_light")
local L2TPv3 = require("apps.keyed_ipv6_tunnel.tunnel").SimpleKeyedTunnel
local ffi = require("ffi")
local C = ffi.C
local AF_INET6 = 10
local lib = require("core.lib")

-- Set to true to enable traffic policing via the rate limiter app
policing = false

-- Compile app configuration from <file> for <pciaddr> and vhost_user
-- <socket>. Returns configuration and zerocopy pairs.
function load (file, pciaddr, sockpath)
   local ports = dofile(file)
   local c = config.new()
   local zerocopy = {} -- {NIC->Virtio} app names to zerocopy link
   for _,t in ipairs(ports) do
      local vlan, mac_address, port_id = t.vlan, t.mac_address, t.port_id
      local name = port_id:gsub("-", "_")
      local NIC = "NIC_"..name
      local Virtio = "Virtio_"..name
      config.app(c, NIC, Intel82599,
		 ([[{pciaddr = %q,
		     vmdq=true,
		     macaddr = %q,
		     vlan=%d}]]):format(pciaddr, mac_address, vlan))
      config.app(c, Virtio, VhostUser, {socket_path=sockpath:format(port_id)})
      local VM_rx, VM_tx = Virtio..".rx", Virtio..".tx"
      if t.ingress_filter then
         local Filter = "Filter_"..name
         config.app(c, Filter, PacketFilter, t.ingress_filter)
         config.link(c, Filter..".tx -> " .. VM_rx)
         VM_rx = Filter..".rx"
      end
      if t.tunnel and t.tunnel.type == "L2TPv3" then
         local Tunnel = "Tunnel_"..name
         local conf = (([[{local_address  = %q,
                           remote_address  = %q,
                           local_cookie = %q,
                           remote_cookie = %q,
                           local_session  = %q,}]])
                       :format(t.tunnel.local_ip, t.tunnel.remote_ip,
                               t.tunnel.local_cookie, t.tunnel.remote_cookie,
                               t.tunnel.session))
         config.app(c, Tunnel, L2TPv3, conf)
         -- Setup IPv6 neighbor discovery/solicitation responder.
         -- This will talk to our local gateway.
         local ND = "ND_"..name
         config.app(c, ND, nd_light,
                    {local_mac = mac_address,
                     local_ip = t.tunnel.local_ip,
                     next_hop = t.tunnel.next_hop})
         -- VM -> Tunnel -> ND <-> Network
         config.link(c, VM_tx.." -> "..Tunnel..".decapsulated")
         config.link(c, Tunnel..".encapsulated -> "..ND..".north")
         -- Network <-> ND -> Tunnel -> VM
         config.link(c, ND..".north -> "..Tunnel..".encapsulated")
         config.link(c, Tunnel..".decapsulated -> "..VM_rx)
         VM_rx, VM_tx = ND..".south", ND..".south"
      end
      if policing and t.gbps then
         local QoS = "QoS_"..name
         local rate = t.gbps * 1000000 / 8
         config.app(c, QoS, RateLimiter, ([[{rate = %d, bucket_capacity = %d}]]):format(rate, rate))
         config.link(c, VM_tx.." -> "..QoS..".rx")
         VM_tx = QoS..".tx"
      end
      config.link(c, NIC..".tx -> "..VM_rx)
      config.link(c, VM_tx.." -> "..NIC..".rx")
      zerocopy[NIC] = Virtio
   end

   -- Return configuration c, and zerocopy pairs.
   return c, zerocopy
end

-- Apply configuration <c> to engine and reset <zerocopy> buffers.
function apply (c, zerocopy)
--   print(config.graphviz(c))
--   main.exit(0)
   engine.configure(c)
   for nic, virtio in pairs(zerocopy) do
      local n = engine.app_table[nic]
      local v = engine.app_table[virtio]
      n:set_rx_buffer_freelist(v:rx_buffers())
   end
end

function selftest ()
   print("selftest: lib.nfv.config")
   local pcideva = os.getenv("SNABB_TEST_INTEL10G_PCIDEVA")
   if not pcideva then
      print("SNABB_TEST_INTEL10G_PCIDEVA was not set\nTest skipped")
      os.exit(engine.test_skipped_code)
   end
   engine.log = true
   for i, confpath in ipairs({"test_fixtures/nfvconfig/switch_nic/x",
                              "test_fixtures/nfvconfig/switch_filter/x",
                              "test_fixtures/nfvconfig/switch_qos/x",
                              "test_fixtures/nfvconfig/switch_tunnel/x",
                              "test_fixtures/nfvconfig/scale_up/y",
                              "test_fixtures/nfvconfig/scale_up/x",
                              "test_fixtures/nfvconfig/scale_change/x",
                              "test_fixtures/nfvconfig/scale_change/y"})
   do
      print("testing:", confpath)
      apply(load(confpath, pcideva, "/dev/null"))
      engine.main({duration = 0.25})
   end
end
