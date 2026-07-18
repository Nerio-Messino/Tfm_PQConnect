-- pqconnect.lua
-- PQConnect Wireshark Lua dissector
-- Supports handshake messages and transport packets from thesis Chapter 3

local pq = Proto("pqconnect", "PQConnect")

pq.prefs.udp_crypto_port = Pref.uint("UDP crypto port", 42424, "PQConnect crypto-server UDP port")
pq.prefs.udp_key_port    = Pref.uint("UDP key port", 42425, "PQConnect key-server UDP port")

local f = pq.fields
local handshakes = {}
local tunnels = {}

-- Generic
f.channel       = ProtoField.string("pqconnect.channel", "Channel")
f.warning       = ProtoField.string("pqconnect.warning", "Warning")
f.raw_payload   = ProtoField.bytes("pqconnect.raw_payload", "Raw payload")
f.phase         = ProtoField.string("pqconnect.phase", "Protocol Phase")
f.direction     = ProtoField.string("pqconnect.direction", "Direction")

-- Handshake
f.msg_type      = ProtoField.bytes("pqconnect.msg_type","PQConnect Message Type")
f.auth_tag      = ProtoField.bytes("pqconnect.auth_tag", "Poly1305 authentication tag")
f.handshake_status = ProtoField.string("pqconnect.handshake_status", "Handshake Status")
f.handshake_key = ProtoField.string("pqconnect.handshake_key", "Connection Key")

--Tunel Tracking
f.tunnel_packet_count = ProtoField.uint32("pqconnect.tunnel_packet_count", "Tunnel Packet Count", base.DEC)
f.last_epoch      = ProtoField.uint16("pqconnect.last_epoch", "Last Seen Epoch", base.DEC)
f.last_packet_no  = ProtoField.uint32("pqconnect.last_packet_no", "Last Seen Packet Number", base.DEC)
f.tunnel_status   = ProtoField.string("pqconnect.tunnel_status", "Tunnel Status")

--Packet Statistics
f.epoch_packet_count    = ProtoField.uint32("pqconnect.epoch_packet_count", "Packets in Current Epoch", base.DEC)
f.total_encrypted_bytes = ProtoField.uint64("pqconnect.total_encrypted_bytes", "Total Encrypted Bytes", base.DEC)
f.average_payload_size  = ProtoField.double("pqconnect.average_payload_size", "Average Encrypted Payload Size")

--Rachet analysis
f.ratchet_status = ProtoField.string("pqconnect.ratchet_status", "Ratchet Status")
f.epoch_jump     = ProtoField.int32("pqconnect.epoch_jump", "Epoch Jump", base.DEC)
f.packet_jump    = ProtoField.int32("pqconnect.packet_jump", "Packet Number Jump", base.DEC)

-- Transport
f.tunnel_id     = ProtoField.bytes("pqconnect.tunnel_id", "Tunnel ID")
f.epoch         = ProtoField.uint16("pqconnect.epoch", "Epoch", base.DEC)
f.packet_no     = ProtoField.uint32("pqconnect.packet_no", "Packet Number", base.DEC)
f.encrypted_ip  = ProtoField.bytes("pqconnect.encrypted_ip", "Encrypted encapsulated IP packet")

-- Initiation packet fields
f.c0   = ProtoField.bytes("pqconnect.c0",    "McEliece ciphertext (c0)")
f.c1   = ProtoField.bytes("pqconnect.c1",   "X25519 ephemeral public key (c1)")
f.tag1 = ProtoField.bytes("pqconnect.tag1", "Poly1305 authentication tag (tag1)")
f.c3   = ProtoField.bytes("pqconnect.c3",   "SNTRUP761 ciphertext (c3)")
f.tag3 = ProtoField.bytes("pqconnect.tag3", "Poly1305 authentication tag (tag3)")


--------------------------------------------------
-- UDP ports
--------------------------------------------------

local crypto_port = 42424
local key_port    = 42425

--------------------------------------------------
-- Message Types
--------------------------------------------------

local MSG_INITIATION = "0100"
local MSG_TUNNEL     = "0200"

--------------------------------------------------
-- Generic lengths
--------------------------------------------------

local MSG_TYPE_LEN        = 2
local TAG_LEN             = 16
local TRANSPORT_HEADER_LEN = 40
local MIN_TRANSPORT_LEN    = TRANSPORT_HEADER_LEN + TAG_LEN

--------------------------------------------------
-- Initiation message lengths
--------------------------------------------------

local C0_LEN = 194
local C1_LEN = 32
local C3_LEN = 1039

--------------------------------------------------
-- Tunnel analysis
--------------------------------------------------

local MAX_EPOCH_ADVANCE  = 2
local MAX_PACKET_ADVANCE = 504

local INITIATION_LEN = MSG_TYPE_LEN + C0_LEN +C1_LEN +TAG_LEN +C3_LEN +TAG_LEN


local function add_bytes_field(buffer, tree, field, range)
    tree:add(field, range)
    tree:add(buffer(0,0),
        string.format("Length: %d bytes (0x%X)", range:len(), range:len()))
end

local function get_message_type(buffer)
    if buffer:len() < 2 then
        return nil
    end

    return tostring(buffer(0, 2):bytes()):gsub(":", ""):lower()
end

local function get_channel(pinfo)
    if pinfo.src_port == key_port or pinfo.dst_port == key_port then
        return "Key-server / bootstrap"
    elseif pinfo.src_port == crypto_port or pinfo.dst_port == crypto_port then
        return "Crypto-server / tunnel"
    end
    return "Unknown PQConnect UDP channel"
end

local function get_direction(pinfo)
    if pinfo.dst_port == crypto_port or pinfo.dst_port == key_port then
        return "Initiator → Responder"
    elseif pinfo.src_port == crypto_port or pinfo.src_port == key_port then
        return "Responder → Initiator"
    end

    return "Unknown"
end

local function add_warning(tree, text)
    tree:add(f.warning, text)
end

local function make_connection_key(pinfo)
    local src = tostring(pinfo.src)
    local dst = tostring(pinfo.dst)
    local sport = tostring(pinfo.src_port)
    local dport = tostring(pinfo.dst_port)

    if pinfo.dst_port == crypto_port or pinfo.dst_port == key_port then
        return src .. ":" .. sport .. " -> " .. dst .. ":" .. dport
    else
        return dst .. ":" .. dport .. " -> " .. src .. ":" .. sport
    end
end

local function tunnel_id_to_string(tvb_range)
    return tostring(tvb_range:bytes())
end

local function get_or_create_tunnel_state(tunnel_id)
    if tunnels[tunnel_id] == nil then
        tunnels[tunnel_id] = {
            packet_count = 0,
            last_epoch = nil,
            last_packet_no = nil,
            epoch_counts = {},
            total_encrypted_bytes = 0
    }
    end

    return tunnels[tunnel_id]
end

local function get_or_create_handshake_state(key)
    if handshakes[key] == nil then
        handshakes[key] = {
            init_seen = false,
            resp_seen = false,
            established = false,
            handshake_type = "Unknown",
            packet_count = 0
        }
    end

    return handshakes[key]
end


local function parse_transport(buffer, pinfo, tree)
    local pkt_len = buffer:len()

    local subtree = tree:add(pq, buffer(), "PQConnect Transport Packet")

    
    --------------------------------------------------
    -- Parse transport header
    --------------------------------------------------

    subtree:add(f.phase, "Transport Data")
    subtree:add(f.direction, get_direction(pinfo))
    subtree:add(f.channel, get_channel(pinfo))

    subtree:add(f.msg_type, buffer(0, MSG_TYPE_LEN))

    local offset = MSG_TYPE_LEN

    local tunnel_id = buffer(offset, 32)
    add_bytes_field(buffer, subtree, f.tunnel_id, tunnel_id)
    offset = offset + 32

    local epoch_range = buffer(offset, 2)
    subtree:add(f.epoch, epoch_range)
    offset = offset + 2

    local packet_range = buffer(offset, 4)
    subtree:add(f.packet_no, packet_range)
    offset = offset + 4

    local encrypted_len = buffer:len() - offset - TAG_LEN

    local encrypted_payload = buffer(offset, encrypted_len)
    add_bytes_field(buffer,subtree, f.encrypted_ip, encrypted_payload)
    offset = offset + encrypted_len

    local auth_tag = buffer(offset, TAG_LEN)
    add_bytes_field(buffer,subtree, f.auth_tag, auth_tag)
    offset = offset + TAG_LEN
    

    local conn_key = make_connection_key(pinfo)
    local hs = handshakes[conn_key]

    subtree:add(f.handshake_key, conn_key)

    if hs and hs.established then
        subtree:add(f.handshake_status, "Transport after established handshake (" .. hs.handshake_type .. ")")
    else
        subtree:add(f.handshake_status, "Transport observed without known completed handshake")
    end

    local tunnel_id_str = tunnel_id_to_string(tunnel_id)
    local epoch = epoch_range:uint()
    local packet_no = packet_range:uint()
    local tunnel_state = get_or_create_tunnel_state(tunnel_id_str)
    --------------------------------------------------
    -- Tunnel analysis
    --------------------------------------------------

    local ratchet_status = "Within expected ratchet window"
    local tunnel_status = "Tunnel tracked"

    local epoch_jump = 0
    local packet_jump = 0

    if tunnel_state.last_epoch ~= nil then

        epoch_jump = epoch - tunnel_state.last_epoch

        if epoch_jump > MAX_EPOCH_ADVANCE then
            ratchet_status = "Possible Ratchet DoS: epoch jump exceeds window"

        elseif epoch_jump < 0 then
            ratchet_status = "Older epoch observed"
        end
    end

    if tunnel_state.last_packet_no ~= nil then

        packet_jump = packet_no - tunnel_state.last_packet_no

        if epoch == tunnel_state.last_epoch then

            if packet_jump > MAX_PACKET_ADVANCE then
                ratchet_status = "Possible Ratchet DoS: packet jump exceeds window"

            elseif packet_jump < 0 then
                ratchet_status = "Out-of-order packet or retransmission"

            elseif packet_jump == 0 then
                ratchet_status = "Duplicate packet number"
            end
        end
    end

    if tunnel_state.last_epoch ~= nil
    and tunnel_state.last_packet_no ~= nil then

        if epoch < tunnel_state.last_epoch then

            tunnel_status = "Older epoch observed"

        elseif epoch == tunnel_state.last_epoch then

            if packet_no < tunnel_state.last_packet_no then
                tunnel_status = "Packet reordering or retransmission observed"

            elseif packet_no == tunnel_state.last_packet_no then
                tunnel_status = "Duplicate packet number observed"
            end

        elseif epoch > tunnel_state.last_epoch then

            tunnel_status = "Epoch advanced"
        end
    end

    --subtree:add(f.epoch_jump, epoch_jump)
    --subtree:add(f.packet_jump, packet_jump)
    --subtree:add(f.ratchet_status, ratchet_status)

    --subtree:add(f.tunnel_packet_count, tunnel_state.packet_count)

    if tunnel_state.last_epoch ~= nil then
        subtree:add(f.last_epoch, tunnel_state.last_epoch)
    end

    if tunnel_state.last_packet_no ~= nil then
        subtree:add(f.last_packet_no, tunnel_state.last_packet_no)
    end

    --subtree:add(f.tunnel_status, tunnel_status)

    tunnel_state.last_epoch = epoch
    tunnel_state.last_packet_no = packet_no

    --------------------------------------------------
    -- Tunnel statistics
    --------------------------------------------------

    tunnel_state.packet_count = tunnel_state.packet_count + 1

    if tunnel_state.epoch_counts[epoch] == nil then
        tunnel_state.epoch_counts[epoch] = 0
    end

    tunnel_state.epoch_counts[epoch] =
        tunnel_state.epoch_counts[epoch] + 1

    tunnel_state.total_encrypted_bytes =
        tunnel_state.total_encrypted_bytes + encrypted_len

    
    local avg_payload_size = tunnel_state.total_encrypted_bytes /  tunnel_state.packet_count
        
    --------------------------------------------------
    -- Display statistics
    --------------------------------------------------

    subtree:add(f.tunnel_packet_count, tunnel_state.packet_count)

    if tunnel_state.last_epoch ~= nil then
        --subtree:add(f.last_epoch, tunnel_state.last_epoch)
    end

    if tunnel_state.last_packet_no ~= nil then
        --subtree:add(f.last_packet_no, tunnel_state.last_packet_no)
    end

    subtree:add(f.tunnel_status, tunnel_status)

    subtree:add(
        buffer(0,0),
        "Packets in Current Epoch: " ..
        tostring(tunnel_state.epoch_counts[epoch])
    )

    subtree:add(
        buffer(0,0),
        "Total Encrypted Bytes: " ..
        tostring(tunnel_state.total_encrypted_bytes)
    )

    subtree:add(
        buffer(0,0),
        string.format(
            "Average Encrypted Payload Size: %.2f",
            avg_payload_size
        )
    )

    --------------------------------------------------
    -- Wireshark columns
    --------------------------------------------------

    pinfo.cols.protocol = "PQConnect"

    pinfo.cols.info =
        string.format(
            "PQConnect Transport | epoch=%d packet=%d",
            epoch,
            packet_no
        )

    
end

local function parse_initiation(buffer, pinfo, tree)
    
    local subtree = tree:add(pq,buffer(),"PQConnect Initiation Message")

    if buffer:len() < MSG_TYPE_LEN then
        add_warning(subtree, "Packet too short")
        return
    end
    

    local expected_len = INITIATION_LEN

    if buffer:len() ~= expected_len then
        add_warning(
            subtree,
            string.format(
                "Unexpected Initiation length (%d bytes, expected %d)",
                buffer:len(),
                expected_len
            )
        )
    end

  
    --subtree:add(f.msg_name, "Initiation Message")

    local conn_key = make_connection_key(pinfo)
    local hs = get_or_create_handshake_state(conn_key)

    hs.packet_count = hs.packet_count + 1
    hs.init_seen = true
    hs.established = true
    hs.handshake_type = "PQConnect Initiation"

    subtree:add(f.handshake_key, conn_key)
    subtree:add(f.handshake_status,"Initiation message observed")

    local summary = subtree:add(buffer(0,0), "Hybrid Cryptographic Components")

    summary:add("Hybrid Key Exchange")
    summary:add("McEliece KEM")
    summary:add("X25519 Ephemeral ECDH")
    summary:add("SNTRUP761 KEM")
    summary:add("ChaCha20-Poly1305 AEAD")

    local offset = 2

    local c0 = buffer(offset, 194)
    add_bytes_field(buffer,subtree, f.c0, c0)
    offset = offset + C0_LEN

    local c1 = buffer(offset, 32)
    add_bytes_field(buffer,subtree, f.c1, c1)
    offset = offset + C1_LEN

    local tag1 = buffer(offset, 16)
    add_bytes_field(buffer,subtree, f.tag1, tag1)
    offset = offset + TAG_LEN

    local c3 = buffer(offset, 1039)
    add_bytes_field(buffer,subtree, f.c3, c3)
    offset = offset + C3_LEN

    local tag3 = buffer(offset, 16)
    add_bytes_field(buffer,subtree, f.tag3, tag3)
    offset = offset + TAG_LEN

    if offset ~= buffer:len() then
    add_warning(subtree,string.format("Parser consumed %d bytes, packet contains %d bytes",offset,buffer:len()))
    end


    pinfo.cols.protocol = "PQConnect"
    pinfo.cols.info = "PQConnect Initiation | len=" .. buffer:len()
end


function pq.dissector(buffer, pinfo, tree)
    local pkt_len = buffer:len()
    if pkt_len == 0 then
        return
    end

    local msg_type = get_message_type(buffer)

    if msg_type == MSG_INITIATION then
        parse_initiation(buffer, pinfo, tree)
        return
    end

    if msg_type == MSG_TUNNEL then
        parse_transport(buffer, pinfo, tree)
        return
    end

    pinfo.cols.protocol = "PQConnect"
    pinfo.cols.info = "PQConnect unknown packet | len=" .. pkt_len

    local subtree = tree:add(
        pq,
        buffer(),
        "PQConnect Unknown Packet"
    )

    subtree:add(f.phase, "Unknown / Unclassified")
    subtree:add(f.direction, get_direction(pinfo))
    subtree:add(f.channel, get_channel(pinfo))

    if pkt_len >= 2 then
        subtree:add(f.msg_type, buffer(0, 2))
    end

    subtree:add(f.raw_payload, buffer())
    add_warning(
        subtree,
        "Packet does not match INITIATION_MSG (01 00) or TUNNEL_MSG (02 00)"
    )
end

function pq.prefs_changed()
    local udp_table = DissectorTable.get("udp.port")

    udp_table:remove(crypto_port, pq)
    udp_table:remove(key_port, pq)

    crypto_port = pq.prefs.udp_crypto_port
    key_port = pq.prefs.udp_key_port

    udp_table:add(crypto_port, pq)
    udp_table:add(key_port, pq)
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(crypto_port, pq)
udp_table:add(key_port, pq)