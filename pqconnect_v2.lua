-- pqconnect_v2.lua
-- Wireshark Lua dissector for PQConnect handshake prototype based on thesis section 3.3

local pq = Proto("pqconnect", "PQConnect")

-- Real message types from the thesis
local msg_types = {
    [0x0001] = "INIT 0-RTT",
    [0x0002] = "INIT 1-RTT",
    [0x0003] = "RESP 1-RTT",
    [0x0004] = "FIN 1-RTT"
}

pq.prefs.udp_crypto_port = Pref.uint("UDP crypto port", 42424, "PQConnect crypto-server UDP port")
pq.prefs.udp_key_port    = Pref.uint("UDP key port", 42425, "PQConnect key-server UDP port")

local f = pq.fields

f.msg_type      = ProtoField.uint16("pqconnect.msg_type", "Message Type", base.HEX)
f.msg_type_name = ProtoField.string("pqconnect.msg_type_name", "Message Type Name")
f.channel       = ProtoField.string("pqconnect.channel", "PQConnect Channel")

f.c0_mceliece   = ProtoField.bytes("pqconnect.c0_mceliece", "c0: McEliece ciphertext")
f.c1_x25519     = ProtoField.bytes("pqconnect.c1_x25519", "c*1: Encrypted Initiator x25519 public key + tag")
f.c2_sntrup_pk  = ProtoField.bytes("pqconnect.c2_sntrup_pk", "c*2: Encrypted Initiator SNTRUP public key + tag")
f.c3_x25519     = ProtoField.bytes("pqconnect.c3_x25519", "c*3: Encrypted Responder x25519 public key + tag")
f.c3_sntrup     = ProtoField.bytes("pqconnect.c3_sntrup", "c*3: Encrypted SNTRUP ciphertext + tag")
f.c5_sntrup     = ProtoField.bytes("pqconnect.c5_sntrup", "c*5: Encrypted SNTRUP ciphertext + tag")

f.raw_payload   = ProtoField.bytes("pqconnect.raw_payload", "Raw Payload")
f.warning       = ProtoField.string("pqconnect.warning", "Warning")

local crypto_port = 42424
local key_port = 42425

local MSG_TYPE_LEN = 2

-- Sizes from thesis
local LEN_MCELIECE_CT = 240
local LEN_X25519_ENC  = 48      -- 32-byte x25519 key + 16-byte Poly1305 tag
local LEN_SNTRUP_PK_ENC = 1234  -- 1218-byte SNTRUP public key + 16-byte tag
local LEN_SNTRUP_CT_ENC = 1063  -- 1047-byte SNTRUP ciphertext + 16-byte tag

local LEN_INIT_0RTT = 2 + LEN_MCELIECE_CT + LEN_X25519_ENC + LEN_SNTRUP_CT_ENC
local LEN_INIT_1RTT = 2 + LEN_MCELIECE_CT + LEN_X25519_ENC + LEN_SNTRUP_PK_ENC
local LEN_RESP_1RTT = 2 + LEN_X25519_ENC + LEN_SNTRUP_CT_ENC
local LEN_FIN_1RTT  = 2 + LEN_SNTRUP_CT_ENC

local function get_channel(pinfo)
    if pinfo.src_port == key_port or pinfo.dst_port == key_port then
        return "Key-server / bootstrap"
    elseif pinfo.src_port == crypto_port or pinfo.dst_port == crypto_port then
        return "Crypto-server / tunnel"
    else
        return "Unknown PQConnect UDP channel"
    end
end

local function add_warning(tree, text)
    tree:add(f.warning, text)
end

local function dissect_init_0rtt(buffer, pinfo, subtree, offset)
    subtree:add(f.c0_mceliece, buffer(offset, LEN_MCELIECE_CT))
    offset = offset + LEN_MCELIECE_CT

    subtree:add(f.c1_x25519, buffer(offset, LEN_X25519_ENC))
    offset = offset + LEN_X25519_ENC

    subtree:add(f.c3_sntrup, buffer(offset, LEN_SNTRUP_CT_ENC))
    offset = offset + LEN_SNTRUP_CT_ENC

    return offset
end

local function dissect_init_1rtt(buffer, pinfo, subtree, offset)
    subtree:add(f.c0_mceliece, buffer(offset, LEN_MCELIECE_CT))
    offset = offset + LEN_MCELIECE_CT

    subtree:add(f.c1_x25519, buffer(offset, LEN_X25519_ENC))
    offset = offset + LEN_X25519_ENC

    subtree:add(f.c2_sntrup_pk, buffer(offset, LEN_SNTRUP_PK_ENC))
    offset = offset + LEN_SNTRUP_PK_ENC

    return offset
end

local function dissect_resp_1rtt(buffer, pinfo, subtree, offset)
    subtree:add(f.c3_x25519, buffer(offset, LEN_X25519_ENC))
    offset = offset + LEN_X25519_ENC

    subtree:add(f.c5_sntrup, buffer(offset, LEN_SNTRUP_CT_ENC))
    offset = offset + LEN_SNTRUP_CT_ENC

    return offset
end

local function dissect_fin_1rtt(buffer, pinfo, subtree, offset)
    subtree:add(f.c5_sntrup, buffer(offset, LEN_SNTRUP_CT_ENC))
    offset = offset + LEN_SNTRUP_CT_ENC

    return offset
end

function pq.dissector(buffer, pinfo, tree)
    local pkt_len = buffer:len()
    if pkt_len < MSG_TYPE_LEN then
        return
    end

    pinfo.cols.protocol = "PQConnect"

    local msg_type = buffer(0, 2):le_uint()
    local msg_name = msg_types[msg_type] or "Unknown"

    pinfo.cols.info = "PQConnect " .. msg_name

    local subtree = tree:add(pq, buffer(), "PQConnect Protocol")
    subtree:add(f.channel, get_channel(pinfo))
    subtree:add_le(f.msg_type, buffer(0, 2))
    subtree:add(f.msg_type_name, msg_name)

    local offset = MSG_TYPE_LEN

    if msg_type == 0x0001 then
        if pkt_len ~= LEN_INIT_0RTT then
            add_warning(subtree, "Unexpected INIT 0-RTT length. Expected " .. LEN_INIT_0RTT .. " bytes, got " .. pkt_len)
        end

        if pkt_len >= LEN_INIT_0RTT then
            dissect_init_0rtt(buffer, pinfo, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end

    elseif msg_type == 0x0002 then
        if pkt_len ~= LEN_INIT_1RTT then
            add_warning(subtree, "Unexpected INIT 1-RTT length. Expected " .. LEN_INIT_1RTT .. " bytes, got " .. pkt_len)
        end

        if pkt_len >= LEN_INIT_1RTT then
            dissect_init_1rtt(buffer, pinfo, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end

    elseif msg_type == 0x0003 then
        if pkt_len ~= LEN_RESP_1RTT then
            add_warning(subtree, "Unexpected RESP 1-RTT length. Expected " .. LEN_RESP_1RTT .. " bytes, got " .. pkt_len)
        end

        if pkt_len >= LEN_RESP_1RTT then
            dissect_resp_1rtt(buffer, pinfo, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end

    elseif msg_type == 0x0004 then
        if pkt_len ~= LEN_FIN_1RTT then
            add_warning(subtree, "Unexpected FIN 1-RTT length. Expected " .. LEN_FIN_1RTT .. " bytes, got " .. pkt_len)
        end

        if pkt_len >= LEN_FIN_1RTT then
            dissect_fin_1rtt(buffer, pinfo, subtree, offset)
        else
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end

    else
        add_warning(subtree, "Unknown PQConnect message type")
        if pkt_len > offset then
            subtree:add(f.raw_payload, buffer(offset, pkt_len - offset))
        end
    end
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