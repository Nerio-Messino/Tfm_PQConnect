-- pqconnect.lua
-- PQConnect Wireshark Lua dissector
-- Supports handshake messages and transport packets from thesis Chapter 3

local pq = Proto("pqconnect", "PQConnect")

pq.prefs.udp_crypto_port = Pref.uint("UDP crypto port", 42424, "PQConnect crypto-server UDP port")
pq.prefs.udp_key_port    = Pref.uint("UDP key port", 42425, "PQConnect key-server UDP port")

local f = pq.fields

-- Generic
f.channel       = ProtoField.string("pqconnect.channel", "Channel")
f.warning       = ProtoField.string("pqconnect.warning", "Warning")
f.raw_payload   = ProtoField.bytes("pqconnect.raw_payload", "Raw payload")

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

local function add_warning(tree, text)
    tree:add(f.warning, text)
end

local function add_aead(subtree, field, buffer, offset, total_len, body_len)
    local aead_tree = subtree:add(field, buffer(offset, total_len))
    aead_tree:add(f.aead_body, buffer(offset, body_len))
    aead_tree:add(f.auth_tag, buffer(offset + body_len, TAG_LEN))
    return offset + total_len
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

    subtree:add(f.channel, get_channel(pinfo))
    subtree:add(f.tunnel_id, buffer(0, 32))
    subtree:add_le(f.epoch, buffer(32, 2))
    subtree:add_le(f.packet_no, buffer(34, 4))

    local encrypted_len = pkt_len - TRANSPORT_HEADER_LEN - TAG_LEN

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