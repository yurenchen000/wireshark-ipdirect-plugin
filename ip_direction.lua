--
-- ip_direction plugins
--
--    show Local,Remote,Direction columns 
-- instead of SRC, DST
-- 						written by yurenchen.com
------------------------------------------------


-- declare some Fields to be read
src_addr = Field.new('ip.src')
dst_addr = Field.new('ip.dst')
ip_proto = Field.new('ip.proto')

src_port = Field.new('tcp.srcport')
dst_port = Field.new('tcp.dstport')

src_arp = Field.new('arp.src.proto_ipv4')
dst_arp = Field.new('arp.dst.proto_ipv4')

src_udp = Field.new('udp.srcport')
dst_udp = Field.new('udp.dstport')

src_hw_addr = Field.new('eth.src')
dst_hw_addr = Field.new('eth.dst')

cap_type = Field.new('frame.encap_type')

-- declare our (pseudo) protocol  // proto name should not contains '.'
ip_direction_proto = Proto('ip_direction', 'TCP Direction Postdissector')

-- create the fields for our 'protocol'
-- create a protoField of a string value, (abbr, name, desc)
 local_addr = ProtoField.string('ip_direction.local',  ' local addr')
remote_addr = ProtoField.string('ip_direction.remote', 'remote addr')
 	 direct = ProtoField.string('ip_direction.direct', 'direct')

 local_port = ProtoField.string('ip_direction.l_port', ' local port')
remote_port = ProtoField.string('ip_direction.r_port', 'remote port')

 local_hw_addr = ProtoField.string('ip_direction.local_hw', ' local hw')
remote_hw_addr = ProtoField.string('ip_direction.remote_hw','remote hw')

 	 note = ProtoField.string('ip_direction.note', 'note')

-- add the field to the protocol
-- assign protoField to dissector 
ip_direction_proto.fields = {local_addr, remote_addr, direct,  local_port, remote_port,  local_hw_addr, remote_hw_addr,  note}

-- Save/Load prefs
function read_conf(fpath)
	local f=io.open(fpath,'r')
	local s=''
	if f then
		s=f:read()
		f:close()
	end
	return s
end
function save_conf(fpath, text)
	local f=io.open(fpath,'w')
	if f then
		f:write(text)
		f:close()
	end
end

function string:split(sep)
   local sep, fields = sep or ":", {}
   local pattern = string.format("([^%s]+)", sep)
   self:gsub(pattern, function(c) fields[#fields+1] = c end)
   return fields
end
function string:is_mac()
	return self:sub(3,3) == ':'
end


local cfg = Dir.personal_config_path('ip_dir_mac.txt')
-- local cfg_mac = read_conf(cfg)
print('cfg:', cfg)
-- mac_arr = cfg_mac:split('\r\n')
-- print('arr:', table.concat(mac_arr,' '))

-- Add prefs
local pref = ip_direction_proto.prefs
-- pref.label_direct_in  = Pref.string ('direct in ', '←', 'label of in  package')
-- pref.label_direct_out = Pref.string ('direct out', '→', 'label of out package')
-- pref.my_mac = Pref.string ('Local MAC/IP', cfg_mac, 'local mac (or ip)')

-- pref.addr1 = Pref.string ('1 ', cfg_mac, 'local mac (or ip)')
-- pref.addr2 = Pref.string ('2 ', cfg_mac, 'local mac (or ip)')
-- pref.addr3 = Pref.string ('3 ', cfg_mac, 'local mac (or ip)')

function pref_init()

	pref.test = Pref.statictext('Local Mac or IP:', 'mac/ip')
	for i = 1, 9 do
		-- pref['addr'..i] = Pref.string (i, mac_arr[i], '')
		pref['addr'..i] = Pref.string(i, '', '')
	end

	--- here got nil // .prefs_changed() called after run
	-- for i = 1, 9 do
	-- 	print(i, pref['addr'..i])
	-- end

end

pref_init()

-- local my_ip ='192.168.0.103'
-- local my_ip ='172.20.1.222'
-- local my_hw = '64:27:37:90:19:21'
-- local my_hw2 = tostring(pref.my_mac)
local my_hw2 = '64:27:37:90:19:21'
local is_mac = my_hw2:sub(3,3) == ':'

local map = {}

function ip_direction_proto.prefs_changed(a)
	-- my_hw2 = tostring(pref.my_mac)
	-- is_mac = my_hw2:sub(3,3) == ':'
	-- save_conf(cfg, my_hw2)
	print('=== prefs_changed:', pref, a, arg) -- args nil

	--- pref is userdata, can't iter
	-- for k,v in pairs(pref) do
	-- 	print(k, v)
	-- end
	map = {}
	for i = 1, 9 do
		local val = pref['addr'..i]
		print(i, type(val), val~='', val)
		if val~='' then
			map[val]=true
		end
	end

end

print('ip_direction loaded: ', os.date('%F %T'))


-- create a function to 'postdissect' each frame
function ip_direction_proto.dissector(buffer, pinfo, tree)
	--print('my_mac2:', pref.my_mac)
	--print('my_mac2:', ip_direction_proto.prefs.my_mac)

	-- obtain the current values the protocol fields
	--[[
	local src_addr_value = src_addr()
	local dst_addr_value = dst_addr()

	if src_addr_value == NULL then
		src_addr_value = src_arp()
		dst_addr_value = dst_arp()
	end
	local src_port_val = src_port()
	local dst_port_val = dst_port()

	if src_port_val == NULL then
		src_port_val = src_udp()
		dst_port_val = dst_udp()
	end
	--]]

	-- detect frame cap: linux cooked OR normal ethernet
	local cap_type_val = tostring(cap_type())
	local d_offset = 0
	if cap_type_val == '25' then -- 25=linux cooked captrue, 1=ethernet
		d_offset = 44
	elseif cap_type_val == '1' then -- ethernet
		d_offset = 42
	else -- unknown: 155=wirshark pdu (etc. logcat)
		return
	end

	-- obtain values from pinfo
	---[[
	local src_port_val = pinfo.src_port
	local dst_port_val = pinfo.dst_port
	local src_addr_value = pinfo.src
	local dst_addr_value = pinfo.dst
	--]]

	local note_value = ''
	local ip_proto_val = tostring(ip_proto() or '')
	-- if pinfo.cols.protocol == 'ICMP' then -- only show in display, lua get is const
	if ip_proto_val == '1' then -- ICMP enum
		src_port_val = pinfo.dst_port
		dst_port_val = pinfo.src_port
		pinfo.cols.info = tostring(pinfo.cols.info) .. ' //'.. tostring(pinfo.dst_port)
	elseif ip_proto_val == '17' then -- UDP enum
		if src_port_val ~= 53 and dst_port_val ~= 53 -- not DNS
			and dst_port_val ~= 1900 -- not SSDP
			and dst_port_val ~= 5353 -- not MDNS
			and dst_port_val ~= 5355 -- not LLMNR
			and dst_port_val ~= 67 and dst_port_val ~= 68 -- not DHCP
			and dst_port_val ~= 137 and dst_port_val ~= 138 -- not NetBIOS
			then 
			--pinfo.cols.info = tostring(pinfo.cols.info) .. ' //'.. ' pkt:'..tostring(buffer:range(0x2a,1)) .. ' cmd:'..tostring(buffer:range(0x2e,2))
			note_value = '//pkt:'..tostring(buffer:range(d_offset, 1)) .. ' cmd:'..tostring(buffer:range(d_offset+4, 2))
		end
	else
		-- return -- unknown, ARP (show mac) or something else
	end

	if src_addr_value and dst_addr_value then
		local src_hw_str = tostring(src_hw_addr() or '')
		local dst_hw_str = tostring(dst_hw_addr() or '')

		src_addr_str = tostring(src_addr_value or '')
		dst_addr_str = tostring(dst_addr_value or '')

		src_port_str = tostring(src_port_val or '')
		dst_port_str = tostring(dst_port_val or '')

		local r_addr
		local l_addr
		local dir_value

		local local_flg = false

		local r_hw_addr
		local l_hw_addr

		-- recognize Local & Remote

		if is_mac then
			-- 使用 MAC 判断包 来源
			-- if src_hw_str == my_hw2 then
			if map[src_hw_str] then
				local_flg = true
			end
		else
			-- 使用 IP 判断包 来源
			-- if src_addr_str == my_hw2 then
			if map[src_addr_str] then
				local_flg = true
			end
		end

		if not local_flg then
			if src_addr_str == dst_addr_str then
				local_flg = src_port_str > dst_port_str
			end
		end


		if local_flg then
			l_addr = src_addr_str
			r_addr = dst_addr_str

			l_hw_addr = src_hw_str
			r_hw_addr = dst_hw_str

			l_port = src_port_str
			r_port = dst_port_str

			dir_value='-->'
		else
			l_addr = dst_addr_str
			r_addr = src_addr_str

			l_hw_addr = dst_hw_str
			r_hw_addr = src_hw_str

			l_port = dst_port_str
			r_port = src_port_str

			-- dir_value=pref.label_direct_in
			dir_value='<--'
		end

		--dir_value = dir_value .. '|' .. tostring(pinfo.p2p_dir)
		--dir_value = dir_value .. '|' .. tostring(pinfo.curr_proto)
		--dir_value = dir_value .. '|' .. tostring(pinfo.cols['protocol']) --ICMP
		--dir_value = dir_value .. '|' .. tostring(pinfo.cols.protocol) --ICMP
		--dir_value = dir_value .. '|' .. tostring(ip_proto()) --ICMP
		--dir_value = dir_value .. '|' .. tostring(pinfo.cols['info'])
		--dir_value = dir_value .. '|' .. tostring(buffer)
		--dir_value = dir_value .. '|' .. tostring(buffer:range(0x2a,10))
		--dir_value = dir_value .. '|' .. ' pkt:'..tostring(buffer:range(0x2a,1)) .. ' cmd:'..tostring(buffer:range(0x2e,2))

		local subtree = tree:add(ip_direction_proto, 'package direction')

		-- show result		
		subtree:add( local_addr, l_addr)
		subtree:add(remote_addr, r_addr)

		subtree:add( local_port, l_port)
		subtree:add(remote_port, r_port)

		subtree:add( direct    , dir_value)
		subtree:add( note      , note_value)

		subtree:add( local_hw_addr, l_hw_addr)
		subtree:add(remote_hw_addr, r_hw_addr)
	end
end

-- register our protocol as a postdissector
register_postdissector(ip_direction_proto)

