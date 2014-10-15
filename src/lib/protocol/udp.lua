module(..., package.seeall)
local ffi = require("ffi")
local C = ffi.C
local header = require("lib.protocol.header")

local udp_header_t = ffi.typeof[[
struct {
   uint16_t    src_port;
   uint16_t    dst_port;
   uint16_t    len;
   uint16_t    checksum;
} __attribute__((packed))
]]

local udp = subClass(header)

-- Class variables
udp._name = "udp"
udp._header_type = udp_header_t
udp._header_ptr_type = ffi.typeof("$*", udp_header_t)
udp._ulp = { method = nil }

-- Class methods

function udp:new (config)
   local o = udp:superClass().new(self)
   o:src_por(tconfig.src_port)
   o:dst_port(config.dst_port)
   o:length(0)
   o:header().checksum = 0
   return o
end

-- Instance methods

function udp:src_port (port)
   local h = self:header()
   if port ~= nil then
      h.src_port = C.htons(port)
   end
   return C.ntohs(h.src_port)
end

function udp:dst_port (port)
   local h = self:header()
   if port ~= nil then
      h.dst_port = C.htons(port)
   end
   return C.ntohs(h.dst_port)
end

function udp:length (len)
   local h = self:header()
   if len ~= nil then
      h.len = C.htons(len)
   end
   return C.ntohs(h.len)
end

function udp:checksum (payload, length, ip)
   local h = self:header()
   if payload then
      local csum = 0
      if ip then
         -- Checksum IP pseudo-header
         local ph = ip:pseudo_header(length + self:sizeof(), 17)
         csum = lib.update_csum(ph, ffi.sizeof(ph), csum)
      end
      -- Add UDP header
      h.checksum = 0
      csum = lib.update_csum(h, self:sizeof(), csum)
      -- Add UDP payload
      csum = lib.update_csum(payload, length, csum)
      h.checksum = C.htons(lib.finish_csum(csum))
   end
   return C.ntohs(h.checksum)
end

-- override the default equality method
function udp:eq (other)
   --compare significant fields
   return (self:src_port() == other:src_port()) and
         (self:dst_port() == other:dst_port()) and
         (self:length() == other:length())
end

return udp
