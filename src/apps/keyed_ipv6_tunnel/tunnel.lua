module(...,package.seeall)

-- http://tools.ietf.org/html/draft-mkonstan-keyed-ipv6-tunnel-01

-- TODO: generalize
local AF_INET6 = 10

local ffi = require("ffi")
local C = ffi.C
local bit = require("bit")

local app = require("core.app")
local link = require("core.link")
local lib = require("core.lib")
local packet = require("core.packet")
local buffer = require("core.buffer")
local config = require("core.config")

local macaddress = require("lib.macaddress")

local pcap = require("apps.pcap.pcap")
local basic_apps = require("apps.basic.basic_apps")

local header_struct_ctype = ffi.typeof[[
struct {
   // ethernet
   char dmac[6];
   char smac[6];
   uint16_t ethertype;
   // ipv6
   uint32_t flow_id; // version, tc, flow_id
   int16_t payload_length;
   int8_t  next_header;
   uint8_t hop_limit;
   char src_ip[16];
   char dst_ip[16];
   // tunnel
   uint32_t session_id;
   char cookie[8];
} __attribute__((packed))
]]

local HEADER_SIZE = ffi.sizeof(header_struct_ctype)
print("HEADER_SIZE", HEADER_SIZE)

local header_array_ctype = ffi.typeof("uint8_t[?]")
local next_header_ctype = ffi.typeof("uint8_t*")
local cookie_ctype = ffi.typeof("uint64_t[1]")
local pcookie_ctype = ffi.typeof("uint64_t*")
local address_ctype = ffi.typeof("uint64_t[2]")
local paddress_ctype = ffi.typeof("uint64_t*")
local plength_ctype = ffi.typeof("int16_t*")
local psession_id_ctype = ffi.typeof("uint32_t*")

local DST_MAC_OFFSET = ffi.offsetof(header_struct_ctype, 'dmac')
local SRC_IP_OFFSET = ffi.offsetof(header_struct_ctype, 'src_ip')
local DST_IP_OFFSET = ffi.offsetof(header_struct_ctype, 'dst_ip')
local COOKIE_OFFSET = ffi.offsetof(header_struct_ctype, 'cookie')
local ETHERTYPE_OFFSET = ffi.offsetof(header_struct_ctype, 'ethertype')
local LENGTH_OFFSET =
   ffi.offsetof(header_struct_ctype, 'payload_length')
local NEXT_HEADER_OFFSET =
   ffi.offsetof(header_struct_ctype, 'next_header')
local SESSION_ID_OFFSET =
   ffi.offsetof(header_struct_ctype, 'session_id')
local FLOW_ID_OFFSET = ffi.offsetof(header_struct_ctype, 'flow_id')
local HOP_LIMIT_OFFSET = ffi.offsetof(header_struct_ctype, 'hop_limit')

local SESSION_COOKIE_SIZE = 12 -- 32 bit session and 64 bit cookie

-- Next Header.
-- Set to 0x73 to indicate that the next header is L2TPv3.
local L2TPV3_NEXT_HEADER = 0x73

local header_template = header_array_ctype(HEADER_SIZE)

-- fill header template with const values
local function prepare_header_template ()
   -- all bytes are zeroed after allocation

   -- IPv6
   header_template[ETHERTYPE_OFFSET] = 0x86
   header_template[ETHERTYPE_OFFSET + 1] = 0xDD

   -- Ver. Set to 0x6 to indicate IPv6.
   -- version is 4 first bits at this offset
   -- no problem to set others 4 bits to zeros - it is already zeros
   header_template[FLOW_ID_OFFSET] = 0x60

   header_template[HOP_LIMIT_OFFSET] = 64
   header_template[NEXT_HEADER_OFFSET] = L2TPV3_NEXT_HEADER

   -- For cases where both tunnel endpoints support one-stage resolution
   -- (IPv6 Address only), this specification recommends setting the
   -- Session ID to all ones for easy identification in case of troubleshooting.
   -- may be overridden by local_session options
   header_template[SESSION_ID_OFFSET] = 0xFF
   header_template[SESSION_ID_OFFSET + 1] = 0xFF
   header_template[SESSION_ID_OFFSET + 2] = 0xFF
   header_template[SESSION_ID_OFFSET + 3] = 0xFF
end

SimpleKeyedTunnel = {}

function SimpleKeyedTunnel:new (confstring)
   local config = confstring and loadstring("return " .. confstring)() or {}
   -- required fields:
   --   local_address, string, ipv6 address
   --   remote_address, string, ipv6 address
   --   local_cookie, 8 bytes string
   --   remote_cookie, 8 bytes string
   -- optional fields:
   --   local_session, unsigned number, must fit to uint32_t
   --   default_gateway_MAC, useful for testing
   --   hop_limit, override default hop limit 64
   assert(
         type(config.local_cookie) == "string"
         and #config.local_cookie == 8,
         "local_cookie should be 8 bytes string"
      )
   assert(
         type(config.remote_cookie) == "string"
         and #config.remote_cookie == 8,
         "remote_cookie should be 8 bytes string"
      )
   local header = header_array_ctype(HEADER_SIZE)
   ffi.copy(header, header_template, HEADER_SIZE)
   ffi.copy(
         header + COOKIE_OFFSET,
         config.local_cookie,
         #config.local_cookie
      )

   -- convert dest, sorce ipv6 addressed to network order binary
   local result =
      ffi.C.inet_pton(AF_INET6, config.local_address, header + SRC_IP_OFFSET)
   assert(result == 1,"malformed IPv6 address: " .. config.local_address)

   result =
      ffi.C.inet_pton(AF_INET6, config.remote_address, header + DST_IP_OFFSET)
   assert(result == 1,"malformed IPv6 address: " .. config.remote_address)

   -- store casted pointers for fast matching
   local remote_address = ffi.cast(paddress_ctype, header + DST_IP_OFFSET)
   local local_address = ffi.cast(paddress_ctype, header + SRC_IP_OFFSET)

   local remote_cookie = ffi.cast(pcookie_ctype, config.remote_cookie)

   if config.local_session then
      local psession = ffi.cast(psession_id_ctype, header + SESSION_ID_OFFSET)
      psession[0] = lib.htonl(config.local_session)
   end
   
   if config.default_gateway_MAC then
      local mac = assert(macaddress:new(config.default_gateway_MAC))
      ffi.copy(header + DST_MAC_OFFSET, mac.bytes, 6)
   end

   if config.hop_limit then
      assert(type(config.hop_limit) == 'number' and
	  config.hop_limit <= 255, "invalid hop limit")
      header[HOP_LIMIT_OFFSET] = config.hop_limit
   end

   local o =
   {
      header = header,
      remote_address = remote_address,
      local_address = local_address,
      remote_cookie = remote_cookie[0]
   }

   return setmetatable(o, {__index = SimpleKeyedTunnel})
end

function SimpleKeyedTunnel:push()
   -- encapsulation path
   local l_in = self.input.decapsulated
   local l_out = self.output.encapsulated
   assert(l_in and l_out)

   while not link.empty(l_in) and not link.full(l_out) do
      local p = packet.want_modify(link.receive(l_in))

      local iovec = p.iovecs[0]

      local new_b = buffer.allocate()
      ffi.copy(new_b.pointer, self.header, HEADER_SIZE)

      -- set payload size
      local plength = ffi.cast(plength_ctype, new_b.pointer + LENGTH_OFFSET)
      plength[0] = lib.htons(SESSION_COOKIE_SIZE + p.length)

      packet.prepend_iovec(p, new_b, HEADER_SIZE)
      link.transmit(l_out, p)
   end

   -- decapsulation path
   l_in = self.input.encapsulated
   l_out = self.output.decapsulated
   assert(l_in and l_out)
   while not link.empty(l_in) and not link.full(l_out) do
      local p = packet.want_modify(link.receive(l_in))

      local iovec = p.iovecs[0]

      -- match next header, cookie, src/dst addresses
      local drop = true
      repeat
         -- support only a whole tunnel header in first iovec at the moment
         if iovec.length < HEADER_SIZE then
            break
         end

         local next_header = ffi.cast(
               next_header_ctype,
               iovec.buffer.pointer + iovec.offset + NEXT_HEADER_OFFSET
            )
         if next_header[0] ~= L2TPV3_NEXT_HEADER then
            break
         end

         local cookie = ffi.cast(
               pcookie_ctype,
               iovec.buffer.pointer + iovec.offset + COOKIE_OFFSET
            )
         if cookie[0] ~= self.remote_cookie then
            break
         end

         local remote_address = ffi.cast(
               paddress_ctype,
               iovec.buffer.pointer + iovec.offset + SRC_IP_OFFSET
            )
         if remote_address[0] ~= self.remote_address[0] or
            remote_address[1] ~= self.remote_address[1]
         then
            break
         end

         local local_address = ffi.cast(
               paddress_ctype,
               iovec.buffer.pointer + iovec.offset + DST_IP_OFFSET
            )
         if local_address[0] ~= self.local_address[0] or
            local_address[1] ~= self.local_address[1]
         then
            break
         end

         drop = false
      until true

      if drop then
         -- discard packet
         packet.deref(p)
      else
         iovec.offset = iovec.offset + HEADER_SIZE
         iovec.length = iovec.length - HEADER_SIZE
         p.length = p.length - HEADER_SIZE
         link.transmit(l_out, p)
      end
   end
end

-- prepare header template to be used by all apps
prepare_header_template()

function selftest ()
   print("Keyed IPv6 tunnel selftest")
   local ok = true

   local input_file = "apps/keyed_ipv6_tunnel/selftest.cap.input"
   local output_file = "apps/keyed_ipv6_tunnel/selftest.cap.output"
   local tunnel_config =
      [[{
      local_address = "00::2:1",
      remote_address = "00::2:1",
      local_cookie = "12345678",
      remote_cookie = "12345678",
      default_gateway_MAC = "a1:b2:c3:d4:e5:f6"
      }
      ]] -- should be symmetric for local "loop-back" test

   buffer.preallocate(10000)
   local c = config.new()
   config.app(c, "source", pcap.PcapReader, input_file)
   config.app(c, "tunnel", SimpleKeyedTunnel, tunnel_config)
   config.app(c, "sink", pcap.PcapWriter, output_file)
   config.link(c, "source.output -> tunnel.decapsulated")
   config.link(c, "tunnel.encapsulated -> tunnel.encapsulated")
   config.link(c, "tunnel.decapsulated -> sink.input")
   app.configure(c)

   app.main({duration = 0.25}) -- should be long enough...
   -- Check results
   if io.open(input_file):read('*a') ~=
      io.open(output_file):read('*a')
   then
      ok = false
   end

   local c = config.new()
   config.app(c, "source", basic_apps.Source)
   config.app(c, "tunnel", SimpleKeyedTunnel, tunnel_config)
   config.app(c, "sink", basic_apps.Sink)
   config.link(c, "source.output -> tunnel.decapsulated")
   config.link(c, "tunnel.encapsulated -> tunnel.encapsulated")
   config.link(c, "tunnel.decapsulated -> sink.input")
   app.configure(c)

   print("run simple one second benchmark ...")
   app.main({duration = 1})
 
   if not ok then
      print("selftest failed")
      os.exit(1)
   end
   print("selftest passed")

end
