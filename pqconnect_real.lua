-- pqconnect.lua
-- PQConnect Wireshark Lua dissector
-- Supports handshake messages and transport packets from thesis Chapter 3

local pq = Proto("pqconnect", "PQConnect")

pq.prefs.udp_crypto_port = Pref.uint("UDP crypto port", 42424, "PQConnect crypto-server UDP port")
pq.prefs.udp_key_port    = Pref.uint("UDP key port", 42425, "PQConnect key-server UDP port")

local f = pq.fields
local handshakes = {}
local tunnels = {}
--------------------------------------------------
-- Pending handshake correlation
--------------------------------------------------

local pending_handshakes = {}

--------------------------------------------------
-- Observed McEliece ciphertexts
--------------------------------------------------

local observed_initiation_c0 = {}

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
--------------------------------------------------
-- Initiation replay analysis
--------------------------------------------------

f.initiation_replay_status = ProtoField.string("pqconnect.initiation_replay_status","Initiation Replay Status")
f.original_initiation_frame = ProtoField.uint32("pqconnect.original_initiation_frame","Original Initiation Frame",base.DEC)

--Tunel Tracking
f.tunnel_packet_count = ProtoField.uint32("pqconnect.tunnel_packet_count", "Tunnel Packet Count", base.DEC)
f.last_epoch      = ProtoField.uint16("pqconnect.last_epoch", "Last Seen Epoch", base.DEC)
f.last_packet_no  = ProtoField.uint32("pqconnect.last_packet_no", "Last Seen Packet Number", base.DEC)
f.tunnel_status   = ProtoField.string("pqconnect.tunnel_status", "Tunnel Status")
f.new_tunnel = ProtoField.bool("pqconnect.new_tunnel","New Tunnel Observed")
f.first_tunnel_frame = ProtoField.uint32("pqconnect.first_tunnel_frame","First Observed Frame",base.DEC)
f.first_tunnel_time = ProtoField.string("pqconnect.first_tunnel_time","First Observed Time")
f.last_tunnel_frame = ProtoField.uint32("pqconnect.last_tunnel_frame","Last Observed Frame",base.DEC)
f.last_tunnel_time = ProtoField.string("pqconnect.last_tunnel_time","Last Observed Time")
f.tunnel_lifetime = ProtoField.double("pqconnect.tunnel_lifetime","Observed Tunnel Lifetime (s)")
f.ratchet_changes = ProtoField.uint32("pqconnect.ratchet_changes","Ratchet Changes",base.DEC)
f.avg_ratchet_interval = ProtoField.double("pqconnect.avg_ratchet_interval","Average Ratchet Interval (s)")
f.packet_event = ProtoField.string("pqconnect.packet_event","Packet Event")

--Packet Statistics
f.epoch_packet_count    = ProtoField.uint32("pqconnect.epoch_packet_count", "Packets in Current Epoch", base.DEC)
f.total_encrypted_bytes = ProtoField.uint64("pqconnect.total_encrypted_bytes", "Total Encrypted Bytes", base.DEC)
f.average_payload_size  = ProtoField.double("pqconnect.average_payload_size", "Average Encrypted Payload Size")

--Rachet analysis
f.ratchet_state = ProtoField.string("pqconnect.ratchet_state", "Ratchet State")
f.epoch_jump     = ProtoField.int32("pqconnect.epoch_jump", "Epoch Jump", base.DEC)
f.packet_jump    = ProtoField.int32("pqconnect.packet_jump", "Packet Number Jump", base.DEC)
f.packet_state = ProtoField.string("pqconnect.packet_state","Packet State")
f.packet_jump = ProtoField.int32("pqconnect.packet_jump","Packet Jump",base.DEC)

--Event
f.event_severity = ProtoField.string("pqconnect.event_severity","Event Severity")

-- Transport
f.tunnel_id     = ProtoField.bytes("pqconnect.tunnel_id", "Tunnel ID")
f.epoch         = ProtoField.uint16("pqconnect.epoch", "Epoch", base.DEC)
f.packet_no     = ProtoField.uint32("pqconnect.packet_no", "Packet Number", base.DEC)
f.encrypted_ip  = ProtoField.bytes("pqconnect.encrypted_ip", "Encrypted encapsulated IP packet")

--------------------------------------------------
-- Initiation cryptographic components
--------------------------------------------------
f.c0 = ProtoField.bytes("pqconnect.c0","c0: McEliece Encapsulation Ciphertext")
f.c1 = ProtoField.bytes("pqconnect.c1","c1: AEAD-encrypted Client Ephemeral X25519 Public Key")
f.tag1 = ProtoField.bytes("pqconnect.tag1","tag1: Poly1305 Authentication Tag for c1")
f.c3 = ProtoField.bytes("pqconnect.c3","c3: AEAD-encrypted SNTRUP761 Encapsulation Ciphertext")
f.tag3 = ProtoField.bytes("pqconnect.tag3","tag3: Poly1305 Authentication Tag for c3")

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


--------------------------------------------------
-- Register tunnel event
--------------------------------------------------

local function register_event(
    tunnel_state,
    pinfo,
    event_type,
    severity,
    description
)

    table.insert(
        tunnel_state.events,
        {
            frame = pinfo.number,
            timestamp = pinfo.abs_ts,
            type = event_type,
            severity = severity,
            description = description
        }
    )

end

--------------------------------------------------
-- Handshake correlation key
--------------------------------------------------

local function make_handshake_key(pinfo)

    return string.format(
        "%s -> %s",
        tostring(pinfo.src),
        tostring(pinfo.dst)
    )

end
--------------------------------------------------
-- Register epoch transition
--------------------------------------------------

local function register_epoch(
    tunnel_state,
    pinfo,
    epoch
)

    table.insert(
        tunnel_state.epoch_history,
        {
            epoch = epoch,
            frame = pinfo.number,
            timestamp = pinfo.abs_ts
        }
    )

end

--------------------------------------------------
-- Analyze Initiation replay
--------------------------------------------------

local function analyze_initiation_replay(
    c0_range,
    pinfo
)

    local c0_key =
        tostring(c0_range:bytes())

    local original_frame =
        observed_initiation_c0[c0_key]

    if original_frame == nil then

        observed_initiation_c0[c0_key] =
            pinfo.number

        return {
            status = "FIRST_OBSERVATION",
            original_frame = pinfo.number,
            is_replay_candidate = false
        }

    end

    if original_frame == pinfo.number then

        return {
            status = "ALREADY_PROCESSED_FRAME",
            original_frame = original_frame,
            is_replay_candidate = false
        }

    end

    return {
        status = "REPEATED_MCELIECE_CIPHERTEXT",
        original_frame = original_frame,
        is_replay_candidate = true
    }

end

--------------------------------------------------
-- Update tunnel statistics
--------------------------------------------------

local function update_tunnel_statistics(
    tunnel_state,
    epoch,
    encrypted_len
)

    tunnel_state.packet_count =
        tunnel_state.packet_count + 1

    if tunnel_state.epoch_counts[epoch] == nil then
        tunnel_state.epoch_counts[epoch] = 0
    end

    tunnel_state.epoch_counts[epoch] =
        tunnel_state.epoch_counts[epoch] + 1

    tunnel_state.total_encrypted_bytes =
        tunnel_state.total_encrypted_bytes + encrypted_len

    local average_payload_size = 0

    if tunnel_state.packet_count > 0 then
        average_payload_size =
            tunnel_state.total_encrypted_bytes
            / tunnel_state.packet_count
    end

    return {
        tunnel_packet_count = tunnel_state.packet_count,
        epoch_packet_count = tunnel_state.epoch_counts[epoch],
        total_encrypted_bytes = tunnel_state.total_encrypted_bytes,
        average_payload_size = average_payload_size
    }

end

--------------------------------------------------
-- Display session summary
--------------------------------------------------

local function display_session_summary(
    subtree,
    buffer,
    tunnel_state,
    lifetime,
    severity
)

    local summary_tree = subtree:add(
        buffer(0,0),
        "Session Summary"
    )

    local last_event = "None"

    if #tunnel_state.events > 0 then
        last_event =
            tunnel_state.events[#tunnel_state.events].type
    end

    summary_tree:add(
        buffer(0,0),
        "Packets Observed: "
        .. tunnel_state.packet_count
    )

    summary_tree:add(
        buffer(0,0),
        "Epochs Observed: "
        .. #tunnel_state.epoch_history
    )

    summary_tree:add(
        buffer(0,0),
        "Ratchet Changes: "
        .. tunnel_state.ratchet_changes
    )

    summary_tree:add(
        buffer(0,0),
        string.format(
            "Tunnel Lifetime: %.2f s",
            lifetime
        )
    )

    summary_tree:add(
        buffer(0,0),
        "Last Event: "
        .. last_event
    )

    summary_tree:add(
        buffer(0,0),
        "Current Severity: "
        .. severity
    )

end


--------------------------------------------------
-- Analyze packet sequence
--------------------------------------------------

local function analyze_packet_sequence(
    tunnel_state,
    packet_no
)

    local analysis = {
        status = "FIRST_PACKET",
        severity = "INFO",
        description = "First packet observed"
    }

    local last = tunnel_state.last_packet_no

    if last == nil then
        return analysis
    end

    if packet_no == last + 1 then

        analysis.status = "NORMAL_SEQUENCE"
        analysis.description =
            "Sequential packet"

    elseif packet_no == last then

        analysis.status = "DUPLICATE_PACKET"
        analysis.severity = "WARNING"
        analysis.description =
            "Duplicate packet number observed"

    elseif packet_no < last then

        analysis.status = "PACKET_ROLLBACK"
        analysis.severity = "WARNING"
        analysis.description =
            string.format(
                "Packet number decreased (%d → %d)",
                last,
                packet_no
            )

    else

        local gap =
            packet_no - last

        if gap <= 10 then

            analysis.status = "PACKET_GAP"
            analysis.severity = "INFO"
            analysis.description =
                string.format(
                    "Gap of %d packets",
                    gap - 1
                )

        else

            analysis.status = "LARGE_PACKET_GAP"
            analysis.severity = "WARNING"
            analysis.description =
                string.format(
                    "Large gap of %d packets",
                    gap - 1
                )

        end

    end

    return analysis

end

--------------------------------------------------
-- Frame processing guard
--------------------------------------------------

local function mark_frame_processed(
    tunnel_state,
    frame_number
)

    if tunnel_state.processed_frames[frame_number] then
        return false
    end

    tunnel_state.processed_frames[frame_number] = true

    return true
end

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

    local sport = tonumber(pinfo.src_port)
    local dport = tonumber(pinfo.dst_port)

    local src_is_pqconnect =
        sport == crypto_port or
        sport == key_port

    local dst_is_pqconnect =
        dport == crypto_port or
        dport == key_port

    -- Client -> PQConnect server
    if dst_is_pqconnect then
        return string.format(
            "%s:%d <-> %s:PQCONNECT",
            src,
            sport,
            dst
        )
    end

    -- PQConnect server -> Client
    if src_is_pqconnect then
        return string.format(
            "%s:%d <-> %s:PQCONNECT",
            dst,
            dport,
            src
        )
    end

    -- Fallback for traffic that does not expose a known PQConnect port
    local endpoint_a = string.format("%s:%d", src, sport)
    local endpoint_b = string.format("%s:%d", dst, dport)

    if endpoint_a < endpoint_b then
        return endpoint_a .. " <-> " .. endpoint_b
    end

    return endpoint_b .. " <-> " .. endpoint_a
end

local function tunnel_id_to_string(tvb_range)
    return tostring(tvb_range:bytes())
end

local function get_or_create_tunnel_state(tunnel_id, pinfo)
    local state = tunnels[tunnel_id]

 
    if state ~= nil then
        state.last_frame = pinfo.number
        state.last_seen = tostring(pinfo.abs_ts)
        state.last_seen_ts = pinfo.abs_ts

        return state, false
    end

    state = {
        -- Identificación temporal
        first_frame = pinfo.number,
        first_seen = tostring(pinfo.abs_ts),
        first_seen_ts = pinfo.abs_ts,
        last_frame = pinfo.number,
        last_seen = tostring(pinfo.abs_ts),
        last_seen_ts = pinfo.abs_ts,

        -- Estado del protocolo
        last_epoch = nil,
        last_packet_no = nil,

        -- Estadísticas
        packet_count = 0,
        epoch_history = {},
        epoch_counts = {},
        events = {},
        ratchet_changes = 0,
        total_encrypted_bytes = 0,
        processed_frames = {},
    }

    tunnels[tunnel_id] = state
    register_event(
        state,
        pinfo,
        "NEW_TUNNEL",
        "INFO",
        "Tunnel first observed"
    )

    return state, true
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

--------------------------------------------------
-- Bidirectional handshake correlation key
--------------------------------------------------

local function make_handshake_key(pinfo)

    local ip1 = tostring(pinfo.src)
    local ip2 = tostring(pinfo.dst)

    if ip1 < ip2 then
        return ip1 .. " <-> " .. ip2
    end

    return ip2 .. " <-> " .. ip1

end


local function parse_transport(buffer, pinfo, tree)
    local pkt_len = buffer:len()

    local subtree = tree:add(pq, buffer(), "PQConnect Transport Packet")

    --------------------------------------------------
    -- Transport packet validation
    --------------------------------------------------

    local packet_len = buffer:len()
    local minimum_len = TRANSPORT_HEADER_LEN + TAG_LEN

    if packet_len < minimum_len then

        add_warning(
            subtree,
            string.format(
                "Truncated Transport message: %d bytes available, %d required",
                packet_len,
                minimum_len
            )
        )

        if packet_len > MSG_TYPE_LEN then

            subtree:add(
                f.raw_payload,
                buffer(
                    MSG_TYPE_LEN,
                    packet_len - MSG_TYPE_LEN
                )
            )

        end

        pinfo.cols.protocol = "PQConnect"
        pinfo.cols.info =
            string.format(
                "PQConnect Transport | truncated | len=%d",
                packet_len
            )

        return

    end


    --------------------------------------------------
    -- General transport information
    --------------------------------------------------

    subtree:add(f.phase, "Transport Data")
    subtree:add(f.direction, get_direction(pinfo))
    subtree:add(f.channel, get_channel(pinfo))

    --------------------------------------------------
    -- Transport header
    --------------------------------------------------

    local header_tree = subtree:add(
        buffer(0, TRANSPORT_HEADER_LEN),
        "Transport Header"
    )

    header_tree:add(
        f.msg_type,
        buffer(0, MSG_TYPE_LEN)
    )

    local offset = MSG_TYPE_LEN

    local tunnel_id = buffer(offset, 32)

    add_bytes_field(
        buffer,
        header_tree,
        f.tunnel_id,
        tunnel_id
    )

    offset = offset + tunnel_id:len()

    local epoch_range = buffer(offset, 2)

    header_tree:add(
        f.epoch,
        epoch_range
    )

    offset = offset + epoch_range:len()

    local packet_range = buffer(offset, 4)

    header_tree:add(
        f.packet_no,
        packet_range
    )

    offset = offset + packet_range:len()

    --------------------------------------------------
    -- Encrypted payload
    --------------------------------------------------

    local encrypted_tree = subtree:add(
        buffer(offset, buffer:len() - offset),
        "Encrypted Payload"
    )

    local encrypted_len = buffer:len() - offset - TAG_LEN

    local encrypted_payload = buffer(offset, encrypted_len)

    add_bytes_field(
        buffer,
        encrypted_tree,
        f.encrypted_ip,
        encrypted_payload
    )

    offset = offset + encrypted_len

    local auth_tag = buffer(offset, TAG_LEN)

    add_bytes_field(
        buffer,
        encrypted_tree,
        f.auth_tag,
        auth_tag
    )

    offset = offset + TAG_LEN

    --------------------------------------------------
    -- Handshake state
    --------------------------------------------------

    local handshake_tree = subtree:add(
        buffer(0, 0),
        "Handshake State"
    )


    --------------------------------------------------
    -- Handshake correlation
    --------------------------------------------------

    local conn_key = make_connection_key(pinfo)

    local hs = handshakes[conn_key]

    local pending = nil

    if hs == nil then

        local hs_key =
            make_handshake_key(pinfo)

        pending =
            pending_handshakes[hs_key]

        if pending ~= nil then
            hs = pending.state
        end

    end

    handshake_tree:add(
        f.handshake_key,
        conn_key
    )

    if hs ~= nil then

        --------------------------------------------------
        -- Observable transition:
        -- Initiation observed -> protected transport observed
        --------------------------------------------------

        if hs.handshake_phase == "INITIATION_OBSERVED" then

            hs.handshake_phase = "SESSION_ACTIVE"

            if hs.first_transport_frame == nil then
                hs.first_transport_frame = pinfo.number
                hs.first_transport_time = pinfo.abs_ts
            end

            if pending ~= nil then
                pending.consumed = true
            end

        end

        handshake_tree:add(
            f.handshake_status,
            hs.handshake_phase
        )

    else

        handshake_tree:add(
            f.handshake_status,
            "TRANSPORT_WITHOUT_OBSERVED_INITIATION"
        )

    end

    
    local tunnel_id_str = tunnel_id_to_string(tunnel_id)
    local epoch = epoch_range:uint()
    local packet_no = packet_range:uint()
    local tunnel_state, is_new_tunnel = get_or_create_tunnel_state(tunnel_id_str, pinfo)
    --local should_update_state = mark_frame_processed(tunnel_state,pinfo.number)
    
    --------------------------------------------------
    -- Tunnel information
    --------------------------------------------------

    local tunnel_tree = subtree:add(
        buffer(0,0),
        "Tunnel Information"
    )

    tunnel_tree:add(
        f.new_tunnel,
        is_new_tunnel
    )

    tunnel_tree:add(
        f.first_tunnel_frame,
        tunnel_state.first_frame
    )

    tunnel_tree:add(
        f.first_tunnel_time,
        tunnel_state.first_seen
    )

    tunnel_tree:add(
        f.last_tunnel_frame,
        tunnel_state.last_frame
    )

    tunnel_tree:add(
        f.last_tunnel_time,
        tunnel_state.last_seen
    )

    local lifetime =
        tunnel_state.last_seen_ts -
        tunnel_state.first_seen_ts

    tunnel_tree:add(
        f.tunnel_lifetime,
        lifetime
    )

    --------------------------------------------------
    -- Packet analysis
    --------------------------------------------------

    local packet_analysis_tree = subtree:add(
        buffer(0,0),
        "Packet Analysis"
    )

    --------------------------------------------------
    -- Current packet event
    --------------------------------------------------

    local packet_event = "NORMAL_TRANSPORT"

    if is_new_tunnel then

        packet_event = "NEW_TUNNEL"

    elseif tunnel_state.last_epoch ~= nil
    and tunnel_state.last_epoch ~= epoch then

        packet_event = "EPOCH_CHANGE"

    end

    packet_analysis_tree:add(
        f.packet_event,
        packet_event
    )

    --------------------------------------------------
    -- Ratchet analysis
    --------------------------------------------------

    local epoch_jump = 0
    local ratchet_state = "Normal"

    if tunnel_state.last_epoch ~= nil then

        epoch_jump = epoch - tunnel_state.last_epoch

        if epoch_jump == 0 then

            ratchet_state = "Same Epoch"

        elseif epoch_jump == 1 then

            ratchet_state = "Normal Ratchet"

        elseif epoch_jump > 1 then

            ratchet_state = "Large Epoch Jump"

        else

            ratchet_state = "Epoch Regression"

        end

    end

    packet_analysis_tree:add(
        f.epoch_jump,
        epoch_jump
    )

    packet_analysis_tree:add(
        f.ratchet_state,
        ratchet_state
    )

    --------------------------------------------------
    -- Packet sequence analysis
    --------------------------------------------------

    local packet_jump = 0
    local packet_state = "Normal"

    if tunnel_state.last_packet_no ~= nil then

        packet_jump =
            packet_no - tunnel_state.last_packet_no

        if epoch ~= tunnel_state.last_epoch then

            packet_state = "New Epoch"

        elseif packet_jump == 1 then

            packet_state = "Sequential"

        elseif packet_jump == 0 then

            packet_state = "Duplicate Packet"

        elseif packet_jump < 0 then

            packet_state = "Packet Reordering"

        else

            packet_state =
                string.format(
                    "Gap (%d packets)",
                    packet_jump - 1
                )

        end

    end

    packet_analysis_tree:add(
        f.packet_jump,
        packet_jump
    )

    packet_analysis_tree:add(
        f.packet_state,
        packet_state
    )


    --------------------------------------------------
    -- Event analysis
    --------------------------------------------------

    local event_tree = subtree:add(
        buffer(0,0),
        "Event Analysis"
    )

    --------------------------------------------------
    -- Event severity
    --------------------------------------------------

    local event_severity = "INFO"

    if packet_event == "NEW_TUNNEL" then

        event_severity = "INFO"

    elseif packet_event == "EPOCH_CHANGE" then

        event_severity = "INFO"

    elseif ratchet_state == "Large Epoch Jump" then

        event_severity = "WARNING"

    elseif ratchet_state == "Epoch Regression" then

        event_severity = "WARNING"

    elseif packet_state == "Packet Reordering" then

        event_severity = "WARNING"

    elseif packet_state == "Duplicate Packet" then

        event_severity = "WARNING"

    elseif string.find(packet_state, "Gap") then

        event_severity = "WARNING"

    end

    event_tree:add(
        f.event_severity,
        event_severity
    )

    --------------------------------------------------
    -- Ratchet history
    --------------------------------------------------

    local ratchet_tree = subtree:add(
        buffer(0,0),
        "Ratchet History"
    )

    --------------------------------------------------
    -- Epoch history
    --------------------------------------------------

    if tunnel_state.last_epoch == nil then

        register_epoch(
            tunnel_state,
            pinfo,
            epoch
        )

    elseif tunnel_state.last_epoch ~= epoch then

        tunnel_state.ratchet_changes =
            tunnel_state.ratchet_changes + 1

        register_epoch(
            tunnel_state,
            pinfo,
            epoch
        )

        register_event(
            tunnel_state,
            pinfo,
            "EPOCH_CHANGE",
            "INFO",
            string.format(
                "Epoch %d → %d",
                tunnel_state.last_epoch,
                epoch
            )
        )

    end

    ratchet_tree:add(
        f.ratchet_changes,
        tunnel_state.ratchet_changes
    )

    --------------------------------------------------
    -- Average ratchet interval
    --------------------------------------------------

    local avg_interval = 0

    if #tunnel_state.epoch_history >= 2 then

        local first =
            tunnel_state.epoch_history[1]

        local last =
            tunnel_state.epoch_history[#tunnel_state.epoch_history]

        avg_interval =
            (last.timestamp - first.timestamp)
            /
            tunnel_state.ratchet_changes

    end

    ratchet_tree:add(
        f.avg_ratchet_interval,
        avg_interval
    )

    --------------------------------------------------
    -- Tunnel statistics
    --------------------------------------------------

    local statistics = update_tunnel_statistics(
        tunnel_state,
        epoch,
        encrypted_len
    )
        
    --------------------------------------------------
    -- Statistics
    --------------------------------------------------

    local statistics_tree = subtree:add(
        buffer(0,0),
        "Statistics"
    )

    statistics_tree:add(
        f.tunnel_packet_count,
        statistics.tunnel_packet_count
    )

    statistics_tree:add(
        buffer(0,0),
        "Packets in Current Epoch: "
        .. tostring(statistics.epoch_packet_count)
    )

    statistics_tree:add(
        buffer(0,0),
        "Total Encrypted Bytes: "
        .. tostring(statistics.total_encrypted_bytes)
    )

    statistics_tree:add(
        buffer(0,0),
        string.format(
            "Average Encrypted Payload Size: %.2f",
            statistics.average_payload_size
        )
    )

    --------------------------------------------------
    -- Session summary
    --------------------------------------------------

    display_session_summary(
        subtree,
        buffer,
        tunnel_state,
        lifetime,
        event_severity
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
    
    local subtree =tree:add(pq,buffer(),"PQConnect Initiation Packet")

    --------------------------------------------------
    -- General information
    --------------------------------------------------

    subtree:add(
        f.phase,
        "Handshake"
    )

    subtree:add(
        f.direction,
        get_direction(pinfo)
    )

    subtree:add(
        f.channel,
        get_channel(pinfo)
    )

    --------------------------------------------------
    -- Initiation packet validation
    --------------------------------------------------

    local packet_len = buffer:len()
    local expected_len = INITIATION_LEN

    if packet_len < MSG_TYPE_LEN then

        add_warning(
            subtree,
            string.format(
                "Truncated Initiation header: %d bytes available, %d required",
                packet_len,
                MSG_TYPE_LEN
            )
        )

        pinfo.cols.protocol = "PQConnect"
        pinfo.cols.info =
            "PQConnect Initiation | truncated header"

        return

    end

    if packet_len < expected_len then

        add_warning(
            subtree,
            string.format(
                "Truncated Initiation message: %d bytes available, %d required",
                packet_len,
                expected_len
            )
        )

        subtree:add(
            f.raw_payload,
            buffer(MSG_TYPE_LEN, packet_len - MSG_TYPE_LEN)
        )

        pinfo.cols.protocol = "PQConnect"
        pinfo.cols.info =
            string.format(
                "PQConnect Initiation | truncated | len=%d",
                packet_len
            )

        return

    end

    if packet_len > expected_len then

        add_warning(
            subtree,
            string.format(
                "Initiation contains %d trailing bytes",
                packet_len - expected_len
            )
        )

    end

    --------------------------------------------------
    -- Handshake header
    --------------------------------------------------

    local header_tree =
        subtree:add(
            buffer(0, MSG_TYPE_LEN),
            "Handshake Header"
        )

    header_tree:add(
        f.msg_type,
        buffer(0, MSG_TYPE_LEN)
    )

    --header_tree:add(f.msg_name,"Initiation Message")

    --------------------------------------------------
    -- Handshake state
    --------------------------------------------------

    local handshake_tree = subtree:add(
        buffer(0,0),
        "Handshake State"
    )

    local conn_key = make_connection_key(pinfo)
    local hs = get_or_create_handshake_state(conn_key)

    --------------------------------------------------
    -- Update observable handshake state
    --------------------------------------------------

    hs.packet_count =
        hs.packet_count + 1

    hs.init_seen = true

    hs.handshake_phase =
        "INITIATION_OBSERVED"

    hs.handshake_type =
        "Hybrid 0-RTT Initiation"

    
    --------------------------------------------------
    -- Register pending handshake
    --------------------------------------------------

    local hs_key =
        make_handshake_key(pinfo)

    pending_handshakes[hs_key] = {
    state = hs,
    consumed = false
    }

    --------------------------------------------------
    -- Display handshake state
    --------------------------------------------------

    handshake_tree:add(
        f.handshake_key,
        conn_key
    )

    handshake_tree:add(
        f.handshake_status,
        hs.handshake_phase
    )

    --------------------------------------------------
    -- Handshake execution state
    --------------------------------------------------

    local flow_tree = subtree:add(
        buffer(0,0),
        "Handshake Execution State"
    )

    --------------------------------------------------
    -- Client-side completed operations
    --------------------------------------------------

    flow_tree:add(
        buffer(0,0),
        "CLIENT OPERATIONS"
    )

    flow_tree:add(
        buffer(0,0),
        "✓ McEliece encapsulation completed (k0 established)"
    )

    flow_tree:add(
        buffer(0,0),
        "✓ Ephemeral X25519 key pair generated"
    )

    flow_tree:add(
        buffer(0,0),
        "✓ Client X25519 public key encrypted with AEAD"
    )

    flow_tree:add(
        buffer(0,0),
        "✓ SNTRUP761 encapsulation generated"
    )

    flow_tree:add(
        buffer(0,0),
        "✓ SNTRUP761 encapsulation encrypted with AEAD"
    )

    flow_tree:add(
        buffer(0,0),
        "✓ Initiation message transmitted"
    )

    --------------------------------------------------
    -- Expected responder operations
    --------------------------------------------------

    flow_tree:add(
        buffer(0,0),
        "RESPONDER EXPECTED ACTIONS"
    )

    flow_tree:add(
        buffer(0,0),
        "• Recover k0 from McEliece decapsulation"
    )

    flow_tree:add(
        buffer(0,0),
        "• Recover client ephemeral X25519 key"
    )

    flow_tree:add(
        buffer(0,0),
        "• Perform two X25519 Diffie-Hellman exchanges"
    )

    flow_tree:add(
        buffer(0,0),
        "• Recover SNTRUP761 encapsulation"
    )

    flow_tree:add(
        buffer(0,0),
        "• Derive Tunnel ID and transport keys"
    )
    --------------------------------------------------
    -- Handshake payload
    --------------------------------------------------

    local payload_tree = subtree:add(
        buffer(MSG_TYPE_LEN),
        "Handshake Payload"
    )

    local offset = MSG_TYPE_LEN

    --------------------------------------------------
    -- c0: McEliece encapsulation
    --------------------------------------------------

    local c0 = buffer(
        offset,
        C0_LEN
    )

    add_bytes_field(
        buffer,
        payload_tree,
        f.c0,
        c0
    )

    offset = offset + C0_LEN

    --------------------------------------------------
    -- Initiation replay analysis
    --------------------------------------------------

    local replay_analysis =
        analyze_initiation_replay(
            c0,
            pinfo
        )

    local replay_tree = subtree:add(
        buffer(0, 0),
        "Initiation Replay Analysis"
    )

    replay_tree:add(
        f.initiation_replay_status,
        replay_analysis.status
    )

    replay_tree:add(
        f.original_initiation_frame,
        replay_analysis.original_frame
    )

    if replay_analysis.is_replay_candidate then

        add_warning(
            replay_tree,
            string.format(
                "McEliece ciphertext already observed in frame %d",
                replay_analysis.original_frame
            )
        )

    end

    --------------------------------------------------
    -- c1
    --------------------------------------------------

    local c1 = buffer(offset, C1_LEN)

    add_bytes_field(
        buffer,
        payload_tree,
        f.c1,
        c1
    )

    offset = offset + C1_LEN

    --------------------------------------------------
    -- tag1
    --------------------------------------------------

    local tag1 = buffer(offset, TAG_LEN)

    add_bytes_field(
        buffer,
        payload_tree,
        f.tag1,
        tag1
    )

    offset = offset + TAG_LEN

    --------------------------------------------------
    -- c3
    --------------------------------------------------

    local c3 = buffer(offset, C3_LEN)

    add_bytes_field(
        buffer,
        payload_tree,
        f.c3,
        c3
    )

    offset = offset + C3_LEN

    --------------------------------------------------
    -- tag3
    --------------------------------------------------

    local tag3 = buffer(offset, TAG_LEN)

    add_bytes_field(
        buffer,
        payload_tree,
        f.tag3,
        tag3
    )

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