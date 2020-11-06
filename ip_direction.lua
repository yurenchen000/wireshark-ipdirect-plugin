--
-- ip.direction plugins
--
--    show Local,Remote,Direction columns 
-- instead of SRC, DST
-- 						written by yurenchen.com
------------------------------------------------


-- declare some Fields to be read
src_addr = Field.new("ip.src")
dst_addr = Field.new("ip.dst")

src_port = Field.new("tcp.srcport")
dst_port = Field.new("tcp.dstport")

src_arp = Field.new("arp.src.proto_ipv4")
dst_arp = Field.new("arp.dst.proto_ipv4")

src_udp = Field.new("udp.srcport")
dst_udp = Field.new("udp.dstport")

src_hw_addr = Field.new("eth.src")
dst_hw_addr = Field.new("eth.dst")

-- declare our (pseudo) protocol
ip_direction_proto = Proto("ip.direction","TCP Direction Postdissector")

-- create the fields for our "protocol"
-- create a protoField of a string value, (abbr, name, desc)
 local_addr = ProtoField.string("ip.direction.local", " local addr")
remote_addr = ProtoField.string("ip.direction.remote","remote addr")
 	 direct = ProtoField.string("ip.direction.direct","direct")

 local_port = ProtoField.string("ip.direction.local_pt", " local port")
remote_port = ProtoField.string("ip.direction.remote_pt","remote port")

 local_hw_addr = ProtoField.string("ip.direction.local_hw", " local hw addr")
remote_hw_addr = ProtoField.string("ip.direction.remote_hw","remote hw addr")

-- add the field to the protocol
-- assign protoField to dissector 
ip_direction_proto.fields = {local_addr,remote_addr,direct, local_port,remote_port, local_hw_addr,remote_hw_addr}

-- save / load
local cfg=Dir.personal_config_path('ip_dir_mac.txt')
function read_conf(fpath)
	local f=io.open(fpath,'r')
	local s=''
	if f then
		s=f:read()
	end
	return s
end
function save_conf(fpath, text)
	local f=io.open(fpath,'w')
	if f then
		f:write(text)
	end
end

cfg_mac=read_conf(cfg)

-- Add prefs
local pref = ip_direction_proto.prefs
pref.label_direct_in  = Pref.string ("direct in ", "←", "label of in  package")
pref.label_direct_out = Pref.string ("direct out", "→", "label of out package")
pref.label_my_mac = Pref.string ("local mac", cfg_mac, "label of local mac")

-- local my_ip='192.168.1.111'
--local my_ip='192.168.1.172'
--local my_hw='e0:06:e6:c9:16:33'
--local my_hw2='aa:bb:cc:dd:ee:ff'
local my_ip='192.168.0.103'
local my_hw='64:27:37:90:19:21'
-- local my_hw2='b8:88:e3:e4:d4:f7'
--local my_hw2='84:90:00:02:03:df'
--local my_hw2='4c:1d:96:a0:c1:2f'
local my_hw2=tostring(pref.label_my_mac)


function ip_direction_proto.prefs_changed()
	my_hw2=tostring(pref.label_my_mac)
	save_conf(cfg, my_hw2)
end

-- create a function to "postdissect" each frame
function ip_direction_proto.dissector(buffer,pinfo,tree)

	--print('my_mac2:', pref.label_my_mac)
	--print('my_mac2:', ip_direction_proto.prefs.label_my_mac)

	-- obtain the current values the protocol fields
	local src_addr_value = src_addr()
	local dst_addr_value = dst_addr()

	local src_port_val = src_port()
	local dst_port_val = dst_port()

	if src_addr_value == NULL then
		src_addr_value = src_arp()
		dst_addr_value = dst_arp()
	end
	if src_port_val == NULL then
		src_port_val = src_udp()
		dst_port_val = dst_udp()
	end

	local src_hw_str = tostring(src_hw_addr())
	local dst_hw_str = tostring(dst_hw_addr())

	if src_addr_value and dst_addr_value then

		src_addr_str = tostring(src_addr_value)
		dst_addr_str = tostring(dst_addr_value)

		src_port_str = tostring(src_port_val or '')
		dst_port_str = tostring(dst_port_val or '')

		local r_addr
		local l_addr
		local dir_value

		local local_flg

		local r_hw_addr
		local l_hw_addr
		
		-- recognize Local & Remote
		-- if src_addr_str == my_ip then
		-- 	local_flg=true
		-- elseif dst_addr_str == my_ip then
		-- 	local_flg=false
		-- elseif string.find(src_addr_str, '^192%.168%.1%.') then
		-- 	local_flg=true
		-- elseif string.find(dst_addr_str, '^192%.168%.1%.') then
		-- 	local_flg=false
		-- elseif string.find(src_addr_str, '^192%.168%.') then
		-- 	local_flg=true
		-- elseif string.find(dst_addr_str, '^192%.168%.') then
		-- 	local_flg=false
		-- end

		-- 使用 MAC 判断包 来源
		if src_hw_str == my_hw or src_hw_str == my_hw2 then
			local_flg=true
		else
			local_flg=false
		end

		if local_flg then
			l_addr=src_addr_str
			r_addr=dst_addr_str

			l_hw_addr = src_hw_str
			r_hw_addr = dst_hw_str

			l_port = src_port_str
			r_port = dst_port_str

			dir_value="-->"
		else
			l_addr=dst_addr_str
			r_addr=src_addr_str

			l_hw_addr = dst_hw_str
			r_hw_addr = src_hw_str

			l_port = dst_port_str
			r_port = src_port_str

			-- dir_value=pref.label_direct_in
			dir_value="<--"
		end

		local subtree = tree:add(ip_direction_proto,"package direction")

		-- show result		
		subtree:add( local_addr,l_addr)
		subtree:add(remote_addr,r_addr)

		subtree:add( local_port, l_port)
		subtree:add(remote_port, r_port)

		subtree:add(direct	   , dir_value)

		subtree:add( local_hw_addr,l_hw_addr)
		subtree:add(remote_hw_addr,r_hw_addr)
	end
end

--print('my_mac:', pref.label_my_mac)
--print('my_mac:', ip_direction_proto.prefs.label_my_mac)

-- register our protocol as a postdissector
register_postdissector(ip_direction_proto)

