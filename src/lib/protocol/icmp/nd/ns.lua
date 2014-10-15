module(..., package.seeall)
local ffi = require("ffi")
local C = ffi.C
local nd_header = require("lib.protocol.icmp.nd.header")

local ns_t = ffi.typeof[[
      struct {
	 uint32_t reserved;
	 uint8_t  target[16];
      }
]]
   
local ns = subClass(nd_header)

-- Class variables
ns._name = "neighbor solicitation"
ns._header_type = ns_t
ns._header_ptr_type = ffi.typeof("$*", ns_t)
ns._ulp = { method = nil }

-- Class methods

function ns:new (target)
   local o = ns:superClass().new(self)
   o:target(target)
   return o
end

-- Instance methods

function ns:target (target)
   if target ~= nil then
      ffi.copy(self:header().target, target, 16)
   end
   return self:header().target
end

function ns:target_eq (target)
   return C.memcmp(target, self:header().target, 16) == 0
end

return ns
