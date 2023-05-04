local ffi = require("ffi");

local client_proxy = {
    --call    sub_10996300 ; 51 C3
    __address = client.find_signature("client.dll", "\x51\xC3");

    cast = function(self, typeof)
        return ffi.cast(ffi.typeof(typeof), self.__address)
    end;

    bind = function(self, typeof, address)
        local cast = self:cast(typeof);

        return function(...)
            return cast(address, ...)
        end
    end;

    call = function(self, typeof, address, ...)
        return self:cast(typeof)(address, ...)
    end;
};

local __VirtualProtect = client_proxy:bind(
    "uintptr_t (__thiscall*)(uintptr_t, void*, uintptr_t, uintptr_t, uintptr_t*)", 

    client_proxy:call(
        "uintptr_t (__thiscall*)(void*, uintptr_t, const char*)",
        ffi.cast("void***", ffi.cast("char*", client.find_signature("client.dll", "\x50\xFF\x15\xCC\xCC\xCC\xCC\x85\xC0\x0F\x84\xCC\xCC\xCC\xCC\x6A\x00")) + 3)[0][0],

        client_proxy:call(
            "uintptr_t (__thiscall*)(void*, const char*)",
            ffi.cast("void***", ffi.cast("char*", client.find_signature("client.dll", "\xC6\x06\x00\xFF\x15\xCC\xCC\xCC\xCC\x50")) + 5)[0][0],
            "kernel32.dll"
        ), --> Returns Kernel32.dll base address <
        
        "VirtualProtect"
    ) --> Returns VirtualProtect Memoryapi address <
);

local VirtualProtect = function(self, lpAddress, dwSize, flNewProtect, lpflOldProtect)
    return __VirtualProtect(ffi.cast("void*", lpAddress), dwSize, flNewProtect, lpflOldProtect)
end;

local vmt_hook = {hooks = {}};

function vmt_hook.new(vt)
    local virtual_table, original_table = ffi.cast("intptr_t**", vt)[0], {};
    local lpflOldProtect = ffi.new("unsigned long[1]");
    local rtn = {}; 

    rtn.hook = function(cast, func, method)
        original_table[method] = virtual_table[method];

        VirtualProtect(virtual_table + method, 4, 0x4, lpflOldProtect)
        virtual_table[method] = ffi.cast("intptr_t", ffi.cast(cast, func))

        VirtualProtect(virtual_table + method, 4, lpflOldProtect[0], lpflOldProtect)
        return ffi.cast(cast, original_table[method])
    end

    rtn.unhook_method = function(method)
        VirtualProtect(virtual_table + method, 4, 0x4, lpflOldProtect)
        virtual_table[method] = original_table[method];

        VirtualProtect(virtual_table + method, 4, lpflOldProtect[0], lpflOldProtect)
        original_table[method] = nil;
    end

    rtn.unhook_all = function()
        for method, _ in pairs(original_table) do
            rtn.unhook_method(method)
        end
    end

    table.insert(vmt_hook.hooks, rtn.unhook)
    return rtn
end

return vmt_hook
