-- Support for basic OO programming.  Apart from the usual
-- incantations of setmetatable(), it implements a simple mechanism to
-- avoid table allocations by recycling objects that have been
-- explicitely declared to no longer be in use.
--
-- All objects are descendants from a simple "elementary class" that
-- implements the basic functionality for the creation and recycling
-- of instance objects through the new() and free() methods.
--
-- Usage:
--   local require("lib.lua.class")
--   local baseClass = require("baseClass")
--   local myclass = subClass(baseClass)
--   local instance = myclass:new()
--   instance:free()
--
-- If baseClass is nil, myclass will be a direct descendant of
-- elementaryClass
--
-- The basic constructor new() either allocates a new instance or
-- re-uses one that has been put on the class's freelist by a previous
-- call of the free() instance method.
--
-- Calls to methods of the super class must use the 'dot' notation and
-- pass the object as argument itself, e.g.
--
--   local myclass = subClass(someClass)
--   function myclass:method(...)
--      myclass:superClass().method(self, ...)
--      -- Customization goes here
--    end
--
-- Note that the superClass method must be called with reference to
-- the class in which the function is defined.  Using
-- self:superClass() would create a loop if the method itself was
-- called from a derived class.

local elementaryClass = {}
elementaryClass._name = "elementary class"

-- Class methods

-- Create a new instance of a class or re-use one from the free list.
-- A recycled object has its instance variable _recycled set to true.
-- A class can use this, for example, to perform clean-up on such an
-- object before re-use.
function elementaryClass:new ()
   assert(self ~= elementaryClass, "Can't instantiate abstract class elementaryClass")
   local instance
   local freelist = self._freelist
   local index = freelist.index
   if index > 0 then
      instance = freelist.list[index]
      instance._recycled = true
      freelist.index = index - 1
   else
      instance = { _recycled = false }
      setmetatable(instance, { __index = self })
   end
   return instance
end

-- Instance methods

function elementaryClass:name()
   return self._name or nil
end

-- Put an instance on the free list for recycling
function elementaryClass:free ()
   local freelist = self:class()._freelist
   local index = freelist.index + 1
   freelist.list[index] = self
   freelist.index = index
end

function subClass (baseClass)
   local baseClass = baseClass or elementaryClass
   local class = { _freelist = { index = 0, list = {} } }
   setmetatable(class, { __index = baseClass })

   function class:class ()
      return class
   end

   function class:superClass ()
      return baseClass
   end

   return class
end
