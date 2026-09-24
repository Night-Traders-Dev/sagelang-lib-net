# DNS record and message parsing utilities
# Parses raw DNS wire-format messages into structured data

proc read_u16_be(bs, off):
    if off + 1 >= len(bs):
        return 0
    return bs[off] * 256 + bs[off + 1]

proc read_u32_be(bs, off):
    if off + 3 >= len(bs):
        return 0
    return bs[off] * 16777216 + bs[off + 1] * 65536 + bs[off + 2] * 256 + bs[off + 3]

# DNS record types
let TYPE_A = 1
let TYPE_NS = 2
let TYPE_CNAME = 5
let TYPE_SOA = 6
let TYPE_PTR = 12
let TYPE_MX = 15
let TYPE_TXT = 16
let TYPE_AAAA = 28
let TYPE_SRV = 33
let TYPE_OPT = 41
let TYPE_ANY = 255

# DNS classes
let CLASS_IN = 1
let CLASS_CH = 3
let CLASS_HS = 4
let CLASS_ANY = 255

# DNS response codes
let RCODE_NOERROR = 0
let RCODE_FORMERR = 1
let RCODE_SERVFAIL = 2
let RCODE_NXDOMAIN = 3
let RCODE_NOTIMP = 4
let RCODE_REFUSED = 5

proc type_name(t):
    if t == 1:
        return "A"
    if t == 2:
        return "NS"
    if t == 5:
        return "CNAME"
    if t == 6:
        return "SOA"
    if t == 12:
        return "PTR"
    if t == 15:
        return "MX"
    if t == 16:
        return "TXT"
    if t == 28:
        return "AAAA"
    if t == 33:
        return "SRV"
    if t == 41:
        return "OPT"
    return "TYPE" + str(t)

proc rcode_name(code):
    if code == 0:
        return "NOERROR"
    if code == 1:
        return "FORMERR"
    if code == 2:
        return "SERVFAIL"
    if code == 3:
        return "NXDOMAIN"
    if code == 4:
        return "NOTIMP"
    if code == 5:
        return "REFUSED"
    return "RCODE" + str(code)

# Read a DNS name from the message (handles compression pointers)
proc read_name(bs, off):
    let parts = []
    let pos = off
    let total_read = 0
    let jumped = false
    let max_iter = 64
    let iterations = 0

    while pos < len(bs) and iterations < max_iter:
        iterations = iterations + 1
        let label_len = bs[pos]

        if label_len == 0:
            if not jumped:
                total_read = total_read + 1
            let name = join(parts, ".")
            return {"name": name, "bytes_read": total_read}

        # Compression pointer (top 2 bits set)
        if (label_len & 192) == 192:
            if pos + 1 >= len(bs):
                let name = join(parts, ".")
                return {"name": name, "bytes_read": total_read}
            let ptr = ((label_len & 63) * 256) + bs[pos + 1]
            if not jumped:
                total_read = total_read + 2
            jumped = true
            pos = ptr
        else:
            # Illegal label length (64-127, not compression, not regular)
            if label_len >= 64:
                let name = join(parts, ".")
                return {"name": name, "bytes_read": total_read}
            # Regular label
            if not jumped:
                total_read = total_read + 1 + label_len
            pos = pos + 1
            if pos + label_len > len(bs):
                let name = join(parts, ".")
                return {"name": name, "bytes_read": total_read}
            let label_parts = []
            for i in range(label_len):
                push(label_parts, chr(bs[pos + i]))
            push(parts, join(label_parts, ""))
            pos = pos + label_len

    let name = join(parts, ".")
    return {"name": name, "bytes_read": total_read}

# Parse DNS message header (12 bytes)
proc parse_header(bs):
    if len(bs) < 12:
        return nil
    let hdr = {}
    hdr["id"] = read_u16_be(bs, 0)
    let flags = read_u16_be(bs, 2)
    hdr["qr"] = (flags >> 15) & 1
    hdr["opcode"] = (flags >> 11) & 15
    hdr["aa"] = (flags >> 10) & 1
    hdr["tc"] = (flags >> 9) & 1
    hdr["rd"] = (flags >> 8) & 1
    hdr["ra"] = (flags >> 7) & 1
    hdr["rcode"] = flags & 15
    hdr["rcode_name"] = rcode_name(flags & 15)
    hdr["is_response"] = hdr["qr"] == 1
    hdr["is_authoritative"] = hdr["aa"] == 1
    hdr["is_truncated"] = hdr["tc"] == 1
    hdr["qdcount"] = read_u16_be(bs, 4)
    hdr["ancount"] = read_u16_be(bs, 6)
    hdr["nscount"] = read_u16_be(bs, 8)
    hdr["arcount"] = read_u16_be(bs, 10)
    return hdr

# Parse a complete DNS message
proc parse_message(bs):
    let hdr = parse_header(bs)
    if hdr == nil:
        return nil
    let msg = {}
    msg["header"] = hdr
    let pos = 12

    # Parse questions
    let questions = []
    for i in range(hdr["qdcount"]):
        if pos >= len(bs):
            msg["questions"] = questions
            return msg
        let nr = read_name(bs, pos)
        pos = pos + nr["bytes_read"]
        if pos + 4 > len(bs):
            msg["questions"] = questions
            return msg
        let q = {}
        q["name"] = nr["name"]
        q["type"] = read_u16_be(bs, pos)
        q["type_name"] = type_name(read_u16_be(bs, pos))
        q["class"] = read_u16_be(bs, pos + 2)
        pos = pos + 4
        push(questions, q)
    msg["questions"] = questions

    # Parse resource records (answers, authority, additional)
    proc parse_rrs(count, start_pos):
        let rrs = []
        let cp = start_pos
        for i in range(count):
            if cp >= len(bs):
                return {"rrs": rrs, "pos": cp}
            let nr2 = read_name(bs, cp)
            cp = cp + nr2["bytes_read"]
            if cp + 10 > len(bs):
                return {"rrs": rrs, "pos": cp}
            let rr = {}
            rr["name"] = nr2["name"]
            rr["type"] = read_u16_be(bs, cp)
            rr["type_name"] = type_name(read_u16_be(bs, cp))
            rr["class"] = read_u16_be(bs, cp + 2)
            rr["ttl"] = read_u32_be(bs, cp + 4)
            let rdlength = read_u16_be(bs, cp + 8)
            cp = cp + 10
            rr["rdlength"] = rdlength

            # Parse rdata based on type
            if rr["type"] == 1 and rdlength == 4:
                rr["address"] = str(bs[cp]) + "." + str(bs[cp + 1]) + "." + str(bs[cp + 2]) + "." + str(bs[cp + 3])
            if rr["type"] == 5 or rr["type"] == 2 or rr["type"] == 12:
                let cnr = read_name(bs, cp)
                rr["target"] = cnr["name"]
            if rr["type"] == 15:
                rr["preference"] = read_u16_be(bs, cp)
                let mnr = read_name(bs, cp + 2)
                rr["exchange"] = mnr["name"]
            if rr["type"] == 28 and rdlength == 16:
                let iparts = []
                for j in range(8):
                    push(iparts, read_u16_be(bs, cp + j * 2))
                rr["address_parts"] = iparts
            if rr["type"] == 16:
                let txt_parts = []
                let tpos = cp
                while tpos < cp + rdlength:
                    let tlen = bs[tpos]
                    tpos = tpos + 1
                    let chunk_parts = []
                    for j in range(tlen):
                        if tpos + j < len(bs):
                            push(chunk_parts, chr(bs[tpos + j]))
                    push(txt_parts, join(chunk_parts, ""))
                    tpos = tpos + tlen
                rr["text"] = join(txt_parts, "")

            let rdata = []
            for j in range(rdlength):
                if cp + j < len(bs):
                    push(rdata, bs[cp + j])
            rr["rdata"] = rdata
            cp = cp + rdlength
            push(rrs, rr)
        return {"rrs": rrs, "pos": cp}

    let ans_result = parse_rrs(hdr["ancount"], pos)
    msg["answers"] = ans_result["rrs"]
    pos = ans_result["pos"]
    let auth_result = parse_rrs(hdr["nscount"], pos)
    msg["authority"] = auth_result["rrs"]
    pos = auth_result["pos"]
    let add_result = parse_rrs(hdr["arcount"], pos)
    msg["additional"] = add_result["rrs"]
    pos = add_result["pos"]

    return msg

# Encode a domain name for DNS wire format
proc encode_name(name):
    let result = []
    let label = ""
    for i in range(len(name)):
        if name[i] == ".":
            push(result, len(label))
            for j in range(len(label)):
                push(result, ord(label[j]))
            label = ""
        else:
            label = label + name[i]
    if len(label) > 0:
        push(result, len(label))
        for j in range(len(label)):
            push(result, ord(label[j]))
    push(result, 0)
    return result

# Build a simple DNS query message
proc build_query(name, record_type, query_id):
    let msg = []
    # Header
    push(msg, (query_id >> 8) & 255)
    push(msg, query_id & 255)
    # Flags: RD=1
    push(msg, 1)
    push(msg, 0)
    # QDCOUNT=1
    push(msg, 0)
    push(msg, 1)
    # ANCOUNT=0
    push(msg, 0)
    push(msg, 0)
    # NSCOUNT=0
    push(msg, 0)
    push(msg, 0)
    # ARCOUNT=0
    push(msg, 0)
    push(msg, 0)
    # Question
    let encoded = encode_name(name)
    for i in range(len(encoded)):
        push(msg, encoded[i])
    # Type
    push(msg, (record_type >> 8) & 255)
    push(msg, record_type & 255)
    # Class IN
    push(msg, 0)
    push(msg, 1)
    return msg
