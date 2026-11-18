"""NetFlow v5, NetFlow v9 and IPFIX (v10) decoding into flat records:
{"src", "dst", "proto", "sport", "dport", "in_if", "out_if", "bytes", "packets"}. Templates are cached per exporter."""
import ipaddress
import struct

TEMPLATES = {}          # (exporter, domain, template_id) -> [(type, length)]

F_BYTES, F_PKTS, F_PROTO, F_SPORT, F_SRC4, F_IN, F_DPORT, F_DST4, F_OUT = 1, 2, 4, 7, 8, 10, 11, 12, 14
F_SRC6, F_DST6, F_OUTBYTES, F_OUTPKTS, F_OCTTOTAL, F_PKTTOTAL = 27, 28, 23, 24, 85, 86


def _int(b):
    return int.from_bytes(b, "big")


def parse(data, exporter):
    if len(data) < 4:
        return []
    ver = struct.unpack("!H", data[:2])[0]
    if ver == 5:
        return parse_v5(data)
    if ver == 9:
        return parse_v9(data, exporter)
    if ver == 10:
        return parse_ipfix(data, exporter)
    raise ValueError(f"unsupported flow version {ver}")


def parse_v5(data):
    count = struct.unpack("!H", data[2:4])[0]
    out = []
    for i in range(count):
        r = data[24 + i * 48: 24 + (i + 1) * 48]
        if len(r) < 48:
            break
        src, dst, _nh, inif, outif, pkts, octets, _first, _last, sport, dport, _pad, _flags, proto = struct.unpack("!4s4s4sHHIIIIHHBBB", r[:39])
        out.append({"src": str(ipaddress.IPv4Address(src)), "dst": str(ipaddress.IPv4Address(dst)), "proto": proto, "sport": sport, "dport": dport,
                    "in_if": inif, "out_if": outif, "bytes": octets, "packets": pkts})
    return out


def _record(fields, raw):
    rec = {"src": "", "dst": "", "proto": 0, "sport": 0, "dport": 0, "in_if": 0, "out_if": 0, "bytes": 0, "packets": 0}
    pos = 0
    for ftype, flen in fields:
        v = raw[pos:pos + flen]
        pos += flen
        if ftype in (F_BYTES, F_OCTTOTAL, F_OUTBYTES):
            rec["bytes"] += _int(v)
        elif ftype in (F_PKTS, F_PKTTOTAL, F_OUTPKTS):
            rec["packets"] += _int(v)
        elif ftype == F_PROTO:
            rec["proto"] = _int(v)
        elif ftype == F_SPORT:
            rec["sport"] = _int(v)
        elif ftype == F_DPORT:
            rec["dport"] = _int(v)
        elif ftype == F_SRC4 and flen == 4:
            rec["src"] = str(ipaddress.IPv4Address(v))
        elif ftype == F_DST4 and flen == 4:
            rec["dst"] = str(ipaddress.IPv4Address(v))
        elif ftype == F_SRC6 and flen == 16:
            rec["src"] = str(ipaddress.IPv6Address(v))
        elif ftype == F_DST6 and flen == 16:
            rec["dst"] = str(ipaddress.IPv6Address(v))
        elif ftype == F_IN:
            rec["in_if"] = _int(v)
        elif ftype == F_OUT:
            rec["out_if"] = _int(v)
    return rec if rec["src"] and rec["dst"] else None


def _sets(data, exporter, domain, start, tmpl_ids, opt_ids, ipfix):
    out, pos = [], start
    while pos + 4 <= len(data):
        set_id, length = struct.unpack("!HH", data[pos:pos + 4])
        if length < 4:
            break
        body = data[pos + 4:pos + length]
        pos += length
        if set_id in tmpl_ids:
            p = 0
            while p + 4 <= len(body):
                tid, cnt = struct.unpack("!HH", body[p:p + 4])
                p += 4
                fields = []
                for _ in range(cnt):
                    if p + 4 > len(body):
                        break
                    ft, fl = struct.unpack("!HH", body[p:p + 4])
                    p += 4
                    if ipfix and ft & 0x8000:          # enterprise-specific element: skip the enterprise number
                        ft &= 0x7FFF
                        p += 4
                        ft = 0xFFFF                     # unknown to us, keep length only
                    fields.append((ft, fl))
                if tid >= 256:
                    TEMPLATES[(exporter, domain, tid)] = fields
        elif set_id in opt_ids:
            continue
        elif set_id >= 256:
            fields = TEMPLATES.get((exporter, domain, set_id))
            if not fields:
                continue                                 # data before its template: dropped until the template arrives
            size = sum(l for _t, l in fields if l != 0xFFFF)
            if size <= 0:
                continue
            for i in range(len(body) // size):
                r = _record(fields, body[i * size:(i + 1) * size])
                if r:
                    out.append(r)
    return out


def parse_v9(data, exporter):
    if len(data) < 20:
        return []
    domain = struct.unpack("!I", data[16:20])[0]
    return _sets(data, exporter, domain, 20, {0}, {1}, False)


def parse_ipfix(data, exporter):
    if len(data) < 16:
        return []
    length = struct.unpack("!H", data[2:4])[0]
    domain = struct.unpack("!I", data[12:16])[0]
    return _sets(data[:length], exporter, domain, 16, {2}, {3}, True)


def service_port(r):
    """The server side of a conversation: the well-known port when one side is ephemeral."""
    s, d = r["sport"], r["dport"]
    if r["proto"] not in (6, 17):
        return 0
    if d and (d < s or s == 0):
        return d
    return s if s < 49152 else d


APPS = {(6, 443): "HTTPS", (17, 443): "QUIC", (6, 80): "HTTP", (17, 53): "DNS", (6, 53): "DNS", (6, 445): "SMB", (6, 3389): "RDP", (6, 22): "SSH",
        (6, 25): "SMTP", (6, 587): "SMTP", (6, 993): "IMAPS", (17, 123): "NTP", (17, 161): "SNMP", (17, 162): "SNMP trap", (17, 514): "Syslog",
        (6, 873): "rsync", (6, 1433): "SQL Server", (6, 3306): "MySQL", (6, 5432): "PostgreSQL", (17, 5060): "SIP", (6, 5060): "SIP",
        (17, 3478): "Teams/STUN", (6, 8080): "HTTP-alt", (6, 389): "LDAP", (6, 636): "LDAPS", (6, 88): "Kerberos", (17, 88): "Kerberos",
        (6, 9100): "Printing", (6, 631): "IPP", (6, 2049): "NFS", (6, 902): "VMware", (6, 49152): "high ports"}
PROTOS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 89: "OSPF", 112: "VRRP"}


def app_name(proto, port):
    if proto not in (6, 17):
        return PROTOS.get(proto, f"IP {proto}")
    return APPS.get((proto, port)) or f"{PROTOS.get(proto, proto)}/{port}"
