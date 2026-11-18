"""Runs one job spec against one device and returns raw output. No Django here: the same file runs inside the
server's worker and inside a remote collector agent. Parsing happens on the server.

Spec:
  {"host": "10.0.0.1", "device_type": "cisco_ios", "port": 22, "username": "...", "password": "...", "secret": "...",
   "timeout": 30,
   "commands": [{"key": "version", "cmd": "show version", "timeout": 60}],            # read-only commands
   "steps": [{"cmd": "copy http://x/img.bin flash:", "expect": "\\?", "answers": [["Destination filename", ""]],
              "timeout": 1800, "fail_on": "Error|%"}],                               # interactive (upgrades)
   "snmp": {"version": "2c", "community": "...", "get": {"sysDescr": "1.3.6.1.2.1.1.1.0"},
            "walk": {"ifDescr": "1.3.6.1.2.1.2.2.1.2"}}}
Result:
  {"outputs": {key: text}, "errors": {key: message}, "steps": [{"cmd", "output", "ok"}],
   "snmp": {"get": {key: value}, "walk": {key: [[oid_suffix, value], ...]}}, "error": "fatal message", "error_kind": "auth|unreachable|..."}
"""
import asyncio
import re
import socket
import time

VERSION = "1.2.0"


def execute(spec):
    started = time.time()
    result = {"outputs": {}, "errors": {}, "steps": [], "snmp": {}}
    try:
        if spec.get("tcp_check"):
            result["tcp"] = tcp_check(spec["host"], spec.get("port") or 22, spec.get("timeout", 5))
        if spec.get("snmp"):
            result["snmp"] = run_snmp(spec["host"], spec["snmp"])
        if spec.get("commands") or spec.get("steps"):
            run_ssh(spec, result)
    except Exception as exc:  # noqa: BLE001 - report every failure back to the server
        result["error"] = str(exc) or exc.__class__.__name__
        result["error_kind"] = classify(exc)
    result["duration"] = round(time.time() - started, 2)
    return result


def tcp_check(host, port, timeout=5):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def classify(exc):
    name = exc.__class__.__name__.lower()
    text = str(exc).lower()
    if "auth" in name or "authentication" in text:
        return "auth"
    if "timeout" in name or "timed out" in text or "unreachable" in text or "refused" in text or "no route" in text:
        return "unreachable"
    return "error"


# ---------------------------------------------------------------- SSH
def run_ssh(spec, result):
    from netmiko import ConnectHandler
    params = {
        "device_type": spec.get("device_type", "cisco_ios"),
        "host": spec["host"],
        "port": spec.get("port") or 22,
        "username": spec.get("username", ""),
        "password": spec.get("password", ""),
        "secret": spec.get("secret", ""),
        "timeout": spec.get("timeout", 30),
        "conn_timeout": spec.get("timeout", 30),
        "auth_timeout": spec.get("timeout", 30),
        "banner_timeout": spec.get("timeout", 30),
        "fast_cli": False,
    }
    with ConnectHandler(**params) as conn:
        if params["secret"]:
            try:
                conn.enable()
            except Exception as exc:  # noqa: BLE001
                result["errors"]["enable"] = str(exc)
        for c in spec.get("commands", []):
            try:
                out = conn.send_command(c["cmd"], read_timeout=c.get("timeout", 90), strip_prompt=True, strip_command=True)
                if _is_error(out):
                    result["errors"][c["key"]] = out.strip()[:300]
                else:
                    result["outputs"][c["key"]] = out
            except Exception as exc:  # noqa: BLE001
                result["errors"][c["key"]] = str(exc)
        failed = False
        for st in spec.get("steps", []):
            if st.get("sleep"):
                time.sleep(min(int(st["sleep"]), 120))
                result["steps"].append({"cmd": st.get("label") or "wait", "output": "", "ok": True})
                continue
            try:
                ok, out = _step(conn, st)
            except Exception as exc:  # noqa: BLE001
                if not st.get("drop_ok"):
                    result["steps"].append({"cmd": st.get("label") or st["cmd"], "output": str(exc), "ok": False})
                    failed = True
                    break
                ok, out = True, f"(session closed while the device reloads: {exc})"
            result["steps"].append({"cmd": st.get("label") or st["cmd"], "output": out[-20000:], "ok": ok})
            if not ok and not st.get("continue_on_fail"):
                failed = True
                break
        if failed and spec.get("on_fail"):
            for st in spec["on_fail"]:
                try:
                    ok, out = _step(conn, st)
                except Exception as exc:  # noqa: BLE001
                    ok, out = False, str(exc)
                result["steps"].append({"cmd": "ROLLBACK: " + (st.get("label") or st["cmd"]), "output": out[-20000:], "ok": ok})
            result["rolled_back"] = all(s["ok"] for s in result["steps"] if s["cmd"].startswith("ROLLBACK"))


# Replies that mean "this command did not run": syntax, permission and authorisation errors from every supported CLI.
# Only short replies are judged, so a long configuration that happens to contain the word "error" is never discarded.
_ERR = re.compile(r"^\s*(% ?(Invalid|Incomplete|Ambiguous|Unknown|Permission denied|Authorization failed|Access denied|Bad|Error)"
                  r"|Command authorization failed|Invalid input|Ambiguous input|Incomplete input|error: |Error: |syntax error|unknown command"
                  r"|Unknown action|command parse error|Command fail|Permission denied|insufficient privilege|not authorized)", re.I | re.M)


def _is_error(out):
    text = (out or "").strip()
    return bool(text) and len(text) <= 600 and bool(_ERR.search(text))


def _step(conn, st):
    """Send one command and answer any confirmation prompts until the prompt (or `expect`) comes back."""
    timeout = st.get("timeout", 120)
    answers = [(re.compile(p, re.I), a) for p, a in st.get("answers", [])]
    fail = re.compile(st["fail_on"], re.I | re.M) if st.get("fail_on") else None
    if st.get("mode") == "config":
        out = conn.send_config_set(st["cmd"].splitlines(), read_timeout=timeout, cmd_verify=False)
        try:
            if conn.check_config_mode():           # Huawei stays in system-view after send_config_set
                out += conn.exit_config_mode()
        except Exception:  # noqa: BLE001
            pass
        return not (fail and fail.search(out)), out
    if st.get("fire_and_forget"):            # reload: the session dies, which is expected
        try:
            out = conn.send_command_timing(st["cmd"], read_timeout=15)
            for _ in range(4):
                for rx, ans in answers:
                    if rx.search(out[-300:]):
                        out += conn.send_command_timing(ans, read_timeout=15)
                        break
                else:
                    break
        except Exception as exc:  # noqa: BLE001
            out = f"(session closed: {exc})"
        return True, out
    out = conn.send_command_timing(st["cmd"], read_timeout=30, last_read=2, strip_prompt=False, strip_command=False)
    deadline = time.time() + timeout
    prompt = re.escape(conn.base_prompt)
    seen = 0                      # answers only look at output that arrived after the previous answer
    while time.time() < deadline:
        fresh = out[seen:][-400:]
        tail = out[-400:]
        hit = False
        for rx, ans in answers:
            if rx.search(fresh):
                seen = len(out)
                out += conn.send_command_timing(ans, read_timeout=30, last_read=2, strip_prompt=False, strip_command=False)
                hit = True
                break
        if hit:
            continue
        if st.get("expect") and re.search(st["expect"], tail, re.M):
            break
        if re.search(r"[<\[]?" + prompt + r"[^\n]*?[#>\]]\s*$", tail):
            break
        time.sleep(3)
        try:
            chunk = conn.read_channel()
        except Exception:  # noqa: BLE001 - the device closed the session (reload)
            chunk = None
        if chunk is None or (not chunk and not _alive(conn)):
            if st.get("drop_ok"):
                return True, out + "\n(session closed by the device: it is reloading)"
            return False, out + "\n(the device closed the session)"
        out += chunk
    else:
        return False, out + "\n(timed out waiting for the device)"
    return not (fail and fail.search(out)), out


def _alive(conn):
    try:
        t = conn.remote_conn.get_transport() if hasattr(conn.remote_conn, "get_transport") else None
        return bool(t and t.is_active()) and not conn.remote_conn.closed
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- SNMP
def run_snmp(host, snmp):
    return asyncio.run(_snmp(host, snmp))


async def _snmp(host, snmp):
    from pysnmp.hlapi.v3arch.asyncio import (CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
                                             UdpTransportTarget, UsmUserData, bulk_walk_cmd, get_cmd)
    from pysnmp.hlapi.v3arch import asyncio as h
    engine = SnmpEngine()
    if snmp.get("version") == "3":
        auth = {"sha": h.usmHMACSHAAuthProtocol, "sha256": h.usmHMAC192SHA256AuthProtocol, "md5": h.usmHMACMD5AuthProtocol}.get(snmp.get("auth_proto") or "")
        priv = {"aes": h.usmAesCfb128Protocol, "aes256": h.usmAesCfb256Protocol, "des": h.usmDESPrivProtocol}.get(snmp.get("priv_proto") or "")
        kw = {}
        if auth:
            kw.update(authKey=snmp.get("auth_key"), authProtocol=auth)
        if priv:
            kw.update(privKey=snmp.get("priv_key"), privProtocol=priv)
        auth_data = UsmUserData(snmp.get("username", ""), **kw)
    else:
        auth_data = CommunityData(snmp.get("community", "public"), mpModel=1)
    target = await UdpTransportTarget.create((host, snmp.get("port", 161)), timeout=snmp.get("timeout", 3), retries=snmp.get("retries", 1))
    out = {"get": {}, "walk": {}}
    if snmp.get("get"):
        names = list(snmp["get"].keys())
        err, status, _idx, binds = await get_cmd(engine, auth_data, target, ContextData(),
                                                 *[ObjectType(ObjectIdentity(snmp["get"][n])) for n in names])
        if err:
            raise TimeoutError(f"SNMP: {err}")
        if status:
            raise RuntimeError(f"SNMP: {status.prettyPrint()}")
        for n, (_oid, val) in zip(names, binds):
            out["get"][n] = _val(val)
    for key, base in (snmp.get("walk") or {}).items():
        rows = []
        prefix = base.strip(".") + "."
        async for err, status, _idx, binds in bulk_walk_cmd(engine, auth_data, target, ContextData(), 0, 25,
                                                             ObjectType(ObjectIdentity(base)), lexicographicMode=False):
            if err:
                if not rows and not out["walk"]:
                    raise TimeoutError(f"SNMP: {err}")
                break
            if status:
                break
            for oid, val in binds:
                o = str(oid)
                if not o.startswith(prefix):
                    break
                rows.append([o[len(prefix):], _val(val)])
            if len(rows) > 50000:
                break
        out["walk"][key] = rows
    engine.close_dispatcher()
    return out


def _val(v):
    cls = v.__class__.__name__
    if cls in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
        return None
    if cls == "OctetString":
        raw = bytes(v)
        try:
            text = raw.decode("utf-8")
            if text.isprintable() or "\n" in text or "\r" in text:
                return text
        except UnicodeDecodeError:
            pass
        return "hex:" + raw.hex()
    if cls in ("Integer", "Integer32", "Counter32", "Counter64", "Gauge32", "Unsigned32", "TimeTicks"):
        return int(v)
    return v.prettyPrint()
