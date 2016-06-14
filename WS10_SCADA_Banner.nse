-- The Head Section --

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Recognize NOVUS WS10 DATA SERVER SCADA SERVICE ON PORT 2001
]]

author = "k0shl@ZPT"
categories = {"NOVUS WS10 DATA SERVER SCADA", "SERVICE"}

-- The Rule Section --

local CMD_LOG = "id 1\r\n"

portrule = shortport.port_or_service(2001)

-- The Action Section --

action = function( host, port )

--Connect NOVUS

local socket = nmap.new_socket()
local status,err = socket:connect(host,port)
if not status then
    return nil
end
print "[+]Connect OK!"

--NOVUS Banner
local status, err = socket:send("id 1\n")
print("[+]Send Banner!")
local s = "02 Logged in"
local status, data = socket:receive()
if not status then
    return nil
end
local q = string.find(data,s)
if q ~= nil then
    return "[+]Find Service NOVUS SCADA!"
else return "[-]Service Could not be NOVUS..."
end
end


