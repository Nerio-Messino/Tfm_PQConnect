function pq.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end

    -- Necesitamos al menos la cabecera (4 bytes)
    if buffer:len() < 4 then
        pinfo.desegment_len = 4 - buffer:len()
        return
    end

    -- Lee length (bytes 2-3) como big-endian (network order)
    local payload_len = buffer(2, 2):uint()
    local total_len = 4 + payload_len

    -- Si aún no tenemos el mensaje completo en este tvb, pedimos reensamblado TCP
    if buffer:len() < total_len then
        pinfo.desegment_len = total_len - buffer:len()
        return
    end

    -- A partir de aquí ya es seguro parsear el mensaje completo
    pinfo.cols.protocol = "PQConnect"
    local subtree = tree:add(pq, buffer(0, total_len), "PQConnect")

    local offset = 0
    subtree:add(f.version, buffer(offset,1)); offset = offset + 1

    local mt = buffer(offset,1):uint()
    subtree:add(f.msg_type, buffer(offset,1)); offset = offset + 1
    subtree:add(f.msg_type_name, msg_types[mt] or "Unknown")

    subtree:add(f.length, buffer(offset,2)); offset = offset + 2

    -- payload completo (payload_len bytes)
    if payload_len > 0 then
        subtree:add(f.payload, buffer(offset, payload_len))
    end

    local mt_name = msg_types[mt] or "Unknown"
    pinfo.cols.info = "PQConnect " .. mt_name .. " (" .. mt .. "), len=" .. payload_len
end