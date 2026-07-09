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
f.msg_type      = ProtoField.uint16("pqconnect.msg_type", "Message Type", base.HEX)
f.msg_name      = ProtoField.string("pqconnect.msg_name", "Message Name")
f.c0_mceliece   = ProtoField.bytes("pqconnect.c0_mceliece", "c0: McEliece ciphertext")
f.c1_x25519     = ProtoField.bytes("pqconnect.c1_x25519", "c*1: encrypted Initiator x25519 public key")
f.c2_sntrup_pk  = ProtoField.bytes("pqconnect.c2_sntrup_pk", "c*2: encrypted Initiator SNTRUP public key")
f.c3_x25519     = ProtoField.bytes("pqconnect.c3_x25519", "c*3: encrypted Responder x25519 public key")
f.c3_sntrup_ct  = ProtoField.bytes("pqconnect.c3_sntrup_ct", "c*3: encrypted SNTRUP ciphertext")
f.c5_sntrup_ct  = ProtoField.bytes("pqconnect.c5_sntrup_ct", "c*5: encrypted SNTRUP ciphertext")
f.aead_body     = ProtoField.bytes("pqconnect.aead_body", "AEAD encrypted body")
f.auth_tag      = ProtoField.bytes("pqconnect.auth_tag", "Poly1305 authentication tag")
f.handshake_status = ProtoField.string("pqconnect.handshake_status", "Handshake Status")
f.handshake_key = ProtoField.string("pqconnect.handshake_key", "Connection Key")

--Tunel Tracking
f.tunnel_packet_count = ProtoField.uint32("pqconnect.tunnel_packet_count", "Tunnel Packet Count", base.DEC)
f.last_epoch      = ProtoField.uint16("pqconnect.last_epoch", "Last Seen Epoch", base.DEC)
f.last_packet_no  = ProtoField.uint32("pqconnect.last_packet_no", "Last Seen Packet Number", base.DEC)
f.tunnel_status   = ProtoField.string("pqconnect.tunnel_status", "Tunnel Status")

--Packet Statistics
f.epoch_packet_count = ProtoField.uint32("pqconnect.epoch_packet_count", "Packets in Current Epoch", base.DEC)
f.total_encrypted_bytes = ProtoField.uint64("pqconnect.total_encrypted_bytes", "Total Encrypted Bytes", base.DEC)
f.average_payload_size = ProtoField.double("pqconnect.average_payload_size", "Average Encrypted Payload Size")

--Rachet analysis
f.ratchet_status = ProtoField.string("pqconnect.ratchet_status", "Ratchet Status")
f.epoch_jump     = ProtoField.int32("pqconnect.epoch_jump", "Epoch Jump", base.DEC)
f.packet_jump    = ProtoField.int32("pqconnect.packet_jump", "Packet Number Jump", base.DEC)

-- Transport
f.tunnel_id     = ProtoField.bytes("pqconnect.tunnel_id", "Tunnel ID")
f.epoch         = ProtoField.uint16("pqconnect.epoch", "Epoch", base.DEC)
f.packet_no     = ProtoField.uint32("pqconnect.packet_no", "Packet Number", base.DEC)
f.encrypted_ip  = ProtoField.bytes("pqconnect.encrypted_ip", "Encrypted encapsulated IP packet")

local crypto_port = 42424
local key_port = 42425

-- Sizes from thesis
local MSG_TYPE_LEN = 2
local TAG_LEN = 16

local LEN_MCELIECE_CT    = 240
local LEN_X25519_PUB     = 32
local LEN_X25519_AEAD    = 48    -- 32 + 16 tag
local LEN_SNTRUP_PK      = 1218
local LEN_SNTRUP_PK_AEAD = 1234  -- 1218 + 16 tag
local LEN_SNTRUP_CT      = 1047
local LEN_SNTRUP_CT_AEAD = 1063  -- 1047 + 16 tag

local LEN_INIT_0RTT      = 2 + LEN_MCELIECE_CT + LEN_X25519_AEAD + LEN_SNTRUP_CT_AEAD -- 1353
local LEN_INIT_1RTT      = 2 + LEN_MCELIECE_CT + LEN_X25519_AEAD + LEN_SNTRUP_PK_AEAD -- 1524
local LEN_RESP_1RTT      = 2 + LEN_X25519_AEAD + LEN_SNTRUP_CT_AEAD                  -- 1113
local LEN_FIN_DEPRECATED = 2 + LEN_SNTRUP_CT_AEAD                                    -- 1065

local TRANSPORT_HEADER_LEN = 32 + 2 + 4
local MIN_TRANSPORT_LEN = TRANSPORT_HEADER_LEN + TAG_LEN

local MAX_EPOCH_ADVANCE = 2
local MAX_PACKET_ADVANCE = 504

local msg_names = {
    [0x0001] = "INIT 0-RTT",
    [0x0002] = "INIT 1-RTT improved",
    [0x0003] = "RESP 1-RTT improved",
    [0x0004] = "FIN 1-RTT first attempt / deprecated"
}

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

local function add_aead(subtree, field, buffer, offset, total_len, body_len)
    local aead_tree = subtree:add(field, buffer(offset, total_len))
    aead_tree:add(f.aead_body, buffer(offset, body_len))
    aead_tree:add(f.auth_tag, buffer(offset + body_len, TAG_LEN))
    return offset + total_len
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

local function parse_init_0rtt(buffer, subtree, offset)
    subtree:add(f.c0_mceliece, buffer(offset, LEN_MCELIECE_CT))
    offset = offset + LEN_MCELIECE_CT

    offset = add_aead(subtree, f.c1_x25519, buffer, offset, LEN_X25519_AEAD, LEN_X25519_PUB)
    offset = add_aead(subtree, f.c3_sntrup_ct, buffer, offset, LEN_SNTRUP_CT_AEAD, LEN_SNTRUP_CT)

    return offset
end

local function parse_init_1rtt(buffer, subtree, offset)
    subtree:add(f.c0_mceliece, buffer(offset, LEN_MCELIECE_CT))
    offset = offset + LEN_MCELIECE_CT

    offset = add_aead(subtree, f.c1_x25519, buffer, offset, LEN_X25519_AEAD, LEN_X25519_PUB)
    offset = add_aead(subtree, f.c2_sntrup_pk, buffer, offset, LEN_SNTRUP_PK_AEAD, LEN_SNTRUP_PK)

    return offset
end

local function parse_resp_1rtt(buffer, subtree, offset)
    offset = add_aead(subtree, f.c3_x25519, buffer, offset, LEN_X25519_AEAD, LEN_X25519_PUB)
    offset = add_aead(subtree, f.c5_sntrup_ct, buffer, offset, LEN_SNTRUP_CT_AEAD, LEN_SNTRUP_CT)

    return offset
end

local function parse_fin_deprecated(buffer, subtree, offset)
    offset = add_aead(subtree, f.c5_sntrup_ct, buffer, offset, LEN_SNTRUP_CT_AEAD, LEN_SNTRUP_CT)
    add_warning(subtree, "Message type 0x04 belongs to the first 1-RTT attempt, not the improved final 1-RTT handshake")
    return offset
end

local function parse_transport(buffer, pinfo, tree)
    local pkt_len = buffer:len()

    local subtree = tree:add(pq, buffer(), "PQConnect Transport Packet")

    local conn_key = make_connection_key(pinfo)
    local hs = handshakes[conn_key]

    subtree:add(f.handshake_key, conn_key)

    if hs and hs.established then
        subtree:add(f.handshake_status, "Transport after established handshake (" .. hs.handshake_type .. ")")
    else
        subtree:add(f.handshake_status, "Transport observed without known completed handshake")
    end

    subtree:add(f.phase, "Transport Data")
    subtree:add(f.direction, get_direction(pinfo))
    subtree:add(f.channel, get_channel(pinfo))
    subtree:add(f.tunnel_id, buffer(0, 32))
    subtree:add_le(f.epoch, buffer(32, 2))
    subtree:add_le(f.packet_no, buffer(34, 4))

    local tunnel_id = tunnel_id_to_string(buffer(0, 32))
    local epoch = buffer(32, 2):le_uint()
    local packet_no = buffer(34, 4):le_uint()

    local tunnel_state = get_or_create_tunnel_state(tunnel_id)

    local ratchet_status = "Within expected ratchet window"
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

        if epoch == tunnel_state.last_epoch and packet_jump > MAX_PACKET_ADVANCE then
            ratchet_status = "Possible Ratchet DoS: packet jump exceeds window"
        elseif epoch == tunnel_state.last_epoch and packet_jump < 0 then
            ratchet_status = "Out-of-order packet or retransmission"
        elseif epoch == tunnel_state.last_epoch and packet_jump == 0 then
            ratchet_status = "Duplicate packet number"
        end
    end

    subtree:add(f.epoch_jump, epoch_jump)
    subtree:add(f.packet_jump, packet_jump)
    subtree:add(f.ratchet_status, ratchet_status)

    tunnel_state.packet_count = tunnel_state.packet_count + 1

    local status = "Tunnel tracked"

    if tunnel_state.last_epoch ~= nil and tunnel_state.last_packet_no ~= nil then
        if epoch < tunnel_state.last_epoch then
            status = "Older epoch observed"
        elseif epoch == tunnel_state.last_epoch and packet_no < tunnel_state.last_packet_no then
            status = "Packet reordering or retransmission observed"
        elseif epoch == tunnel_state.last_epoch and packet_no == tunnel_state.last_packet_no then
            status = "Duplicate packet number observed"
        elseif epoch > tunnel_state.last_epoch then
            status = "Epoch advanced"
        end
    end

    subtree:add(f.tunnel_packet_count, tunnel_state.packet_count)

    if tunnel_state.last_epoch ~= nil then
        subtree:add(f.last_epoch, tunnel_state.last_epoch)
    end

    if tunnel_state.last_packet_no ~= nil then
        subtree:add(f.last_packet_no, tunnel_state.last_packet_no)
    end

    subtree:add(f.tunnel_status, status)

    tunnel_state.last_epoch = epoch
    tunnel_state.last_packet_no = packet_no

    local encrypted_len = pkt_len - TRANSPORT_HEADER_LEN - TAG_LEN

    if tunnel_state.epoch_counts[epoch] == nil then
        tunnel_state.epoch_counts[epoch] = 0
    end

    tunnel_state.epoch_counts[epoch] = tunnel_state.epoch_counts[epoch] + 1
    tunnel_state.total_encrypted_bytes = tunnel_state.total_encrypted_bytes + encrypted_len

    local avg_payload_size = 0
    if tunnel_state.packet_count > 0 then
        avg_payload_size = tunnel_state.total_encrypted_bytes / tunnel_state.packet_count
    end

    subtree:add(f.epoch_packet_count, tunnel_state.epoch_counts[epoch])
    subtree:add(f.total_encrypted_bytes, tunnel_state.total_encrypted_bytes)
    subtree:add(f.average_payload_size, avg_payload_size)

    if encrypted_len > 0 then
        subtree:add(f.encrypted_ip, buffer(TRANSPORT_HEADER_LEN, encrypted_len))
    else
        add_warning(subtree, "No encrypted IP payload present")
    end

    subtree:add(f.auth_tag, buffer(pkt_len - TAG_LEN, TAG_LEN))

    pinfo.cols.protocol = "PQConnect"
    pinfo.cols.info = "PQConnect Transport | epoch=" ..
        buffer(32,2):le_uint() .. " packet=" .. buffer(34,4):le_uint()
end

local function parse_handshake(buffer, pinfo, tree, msg_type)
    local pkt_len = buffer:len()
    local msg_name = msg_names[msg_type] or "Unknown handshake message"

    local subtree = tree:add(pq, buffer(), "PQConnect Handshake: " .. msg_name)

    local conn_key = make_connection_key(pinfo)
    local hs = get_or_create_handshake_state(conn_key)

    hs.packet_count = hs.packet_count + 1

    if msg_type == 0x0001 then
        hs.init_seen = true
        hs.established = true
        hs.handshake_type = "0-RTT"
    elseif msg_type == 0x0002 then
        hs.init_seen = true
        hs.handshake_type = "1-RTT"
    elseif msg_type == 0x0003 then
        hs.resp_seen = true
        if hs.init_seen then
            hs.established = true
        end
    elseif msg_type == 0x0004 then
        hs.handshake_type = "1-RTT first attempt / deprecated"
    end

    local status = "Unknown"

    if hs.established then
        status = "Handshake established (" .. hs.handshake_type .. ")"
    elseif hs.init_seen and not hs.resp_seen then
        status = "INIT seen, waiting for RESP"
    elseif hs.resp_seen and not hs.init_seen then
        status = "RESP seen without previous INIT"
    end

    subtree:add(f.handshake_key, conn_key)
    subtree:add(f.handshake_status, status)

    subtree:add(f.phase, "Handshake")
    subtree:add(f.direction, get_direction(pinfo))
    subtree:add(f.channel, get_channel(pinfo))
    subtree:add_le(f.msg_type, buffer(0, 2))
    subtree:add(f.msg_name, msg_name)

    local offset = MSG_TYPE_LEN

    if msg_type == 0x0001 then
        if pkt_len ~= LEN_INIT_0RTT then
            add_warning(subtree, "Unexpected INIT 0-RTT length. Expected " .. LEN_INIT_0RTT .. ", got " .. pkt_len)
        end
        if pkt_len >= LEN_INIT_0RTT then
            parse_init_0rtt(buffer, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end

    elseif msg_type == 0x0002 then
        if pkt_len ~= LEN_INIT_1RTT then
            add_warning(subtree, "Unexpected INIT 1-RTT length. Expected " .. LEN_INIT_1RTT .. ", got " .. pkt_len)
        end
        if pkt_len >= LEN_INIT_1RTT then
            parse_init_1rtt(buffer, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end

    elseif msg_type == 0x0003 then
        if pkt_len ~= LEN_RESP_1RTT then
            add_warning(subtree, "Unexpected RESP 1-RTT length. Expected " .. LEN_RESP_1RTT .. ", got " .. pkt_len)
        end
        if pkt_len >= LEN_RESP_1RTT then
            parse_resp_1rtt(buffer, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end

    elseif msg_type == 0x0004 then
        if pkt_len ~= LEN_FIN_DEPRECATED then
            add_warning(subtree, "Unexpected deprecated FIN length. Expected " .. LEN_FIN_DEPRECATED .. ", got " .. pkt_len)
        end
        if pkt_len >= LEN_FIN_DEPRECATED then
            parse_fin_deprecated(buffer, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end
    end

    pinfo.cols.protocol = "PQConnect"
    pinfo.cols.info = "PQConnect Handshake | " .. msg_name .. " | len=" .. pkt_len
end

function pq.dissector(buffer, pinfo, tree)
    local pkt_len = buffer:len()
    if pkt_len == 0 then return end

    local possible_msg_type = nil
    if pkt_len >= 2 then
        possible_msg_type = buffer(0, 2):le_uint()
    end

    -- Handshake messages have explicit 16-bit little-endian message types.
    if possible_msg_type == 0x0001 or
       possible_msg_type == 0x0002 or
       possible_msg_type == 0x0003 or
       possible_msg_type == 0x0004 then
        parse_handshake(buffer, pinfo, tree, possible_msg_type)
        return
    end

    -- Transport packets do not start with msg.type; they start with tunnelID.
    if pkt_len >= MIN_TRANSPORT_LEN then
        parse_transport(buffer, pinfo, tree)
        return
    end

    -- Fallback
    pinfo.cols.protocol = "PQConnect"
    pinfo.cols.info = "PQConnect unknown/short packet"

    local subtree = tree:add(pq, buffer(), "PQConnect Unknown Packet")
    subtree:add(f.phase, "Unknown / Unclassified")
    subtree:add(f.direction, get_direction(pinfo))
    subtree:add(f.channel, get_channel(pinfo))
    subtree:add(f.raw_payload, buffer())
    add_warning(subtree, "Packet does not match known handshake or transport format")
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