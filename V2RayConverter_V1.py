#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  V2Ray Converter v1.0  —  V2Ray / Xray  URI ↔ JSON Converter                ║
║  Single-file PyQt6 application                                               ║
║                                                                              ║
║  Supports all major protocols and transports:                                ║
║   Protocols : VLESS, VMess, Trojan, Shadowsocks                              ║
║   Transports: ws, tcp/raw, xhttp/splithttp, h2, grpc,                       ║
║               httpupgrade, kcp/mkcp, quic                                   ║
║   Security  : tls, reality, none                                             ║
║   Extras    : flow (xtls-rprx-vision), allowInsecure,                       ║
║               fingerprint, ALPN, REALITY (pbk/sid/spx)                      ║
║                                                                              ║
║  Features:                                                                   ║
║   • Light / Dark theme toggle in header                                      ║
║   • Paste or load V2Ray JSON configs / proxy URIs                            ║
║   • Bidirectional: JSON → URI  and  URI → JSON                               ║
║   • Auto-detect direction or force a specific mode                           ║
║   • Batch: multiple configs or URIs processed at once                        ║
║   • Copy output to clipboard or save to file                                 ║
║   • "Use as Input" button for chained conversions                            ║
║   • Drag-and-drop file support                                               ║
║   • Detailed operation log with timestamps                                   ║
║   • JSON config file (saves user preferences)                                ║
║   • QThread worker — UI never freezes on large batches                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STANDARD LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
import json
import sys
import re
import base64
from copy import deepcopy
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse, quote, unquote

# ─────────────────────────────────────────────────────────────────────────────
#  PyQt6 IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
from PyQt6.QtCore import (
    Qt,
    QThread,
    pyqtSignal,
    QTimer,
    QDateTime,
)
from PyQt6.QtGui import (
    QFont,
    QIcon,
    QColor,
    QAction,
    QDragEnterEvent,
    QDropEvent,
)
from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QFileDialog,
    QMessageBox,
    QFrame,
    QRadioButton,
    QButtonGroup,
    QTextEdit,
    QGroupBox,
    QSplitter,
    QScrollArea,
    QStatusBar,
    QMenuBar,
    QMenu,
    QDialog,
    QSizePolicy,
)

# ══════════════════════════════════════════════════════════════════════════════
#  APP METADATA
# ══════════════════════════════════════════════════════════════════════════════
APP_NAME = "V2Ray Converter"
APP_VERSION = "1.0"
APP_COMPANY = "SPARKS"
CONFIG_FILE = "v2ray_converter_config.json"

# ══════════════════════════════════════════════════════════════════════════════
#  V2RAY / XRAY  ←→  VLESS / VMESS / TROJAN  URI / JSON  CONVERTER  LOGIC
# ══════════════════════════════════════════════════════════════════════════════

# ─── PARAM ORDER (mirrors what real clients produce) ─────────────────────────
VLESS_PARAM_ORDER = [
    "encryption",
    "security",
    "type",
    "headerType",
    "path",
    "host",
    "mode",
    "serviceName",
    "sni",
    "fp",
    "pbk",
    "sid",
    "spx",
    "alpn",
    "allowInsecure",
    "flow",
    "quicSecurity",
    "key",
    "seed",
    "mtu",
    "tti",
    "uplinkCapacity",
    "downlinkCapacity",
]

# ─── TRANSPORT ALIAS NORMALISATION ───────────────────────────────────────────
_NET_ALIASES = {
    "websocket": "ws",
    "raw": "tcp",
    "splithttp": "xhttp",
    "http": "h2",
    "mkcp": "kcp",
}


def _norm_net(net: str) -> str:
    return _NET_ALIASES.get(net, net) if net else "tcp"


# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _fix_surrogate_pairs(text: str) -> str:
    """Replace \\uD800-\\uDFFF surrogate pairs in JSON strings with real chars."""

    def _replace(m):
        hi = int(m.group(1), 16)
        lo = int(m.group(2), 16)
        cp = 0x10000 + (hi - 0xD800) * 0x400 + (lo - 0xDC00)
        return chr(cp)

    return re.sub(
        r"\\u([dD][89aAbB][0-9a-fA-F]{2})\\u([dD][cCdDeEfF][0-9a-fA-F]{2})",
        _replace,
        text,
    )


def _pct(value: str) -> str:
    return quote(str(value), safe="")


def _build_query(params: dict) -> str:
    parts = []
    for key in VLESS_PARAM_ORDER:
        if key in params:
            parts.append(f"{key}={_pct(params[key])}")
    for key, val in params.items():
        if key not in VLESS_PARAM_ORDER:
            parts.append(f"{key}={_pct(val)}")
    return "&".join(parts)


def _parse_query(qs: str) -> dict:
    params = {}
    for part in qs.split("&"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            params[k] = unquote(v)
        else:
            params[part] = ""
    return params


def _find_proxy_outbound(config: dict) -> dict:
    proxy_protocols = {
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
        "ss",
        "socks",
        "http",
        "wireguard",
        "hysteria",
    }
    for ob in config.get("outbounds", []):
        prot = ob.get("protocol", "").lower()
        tag = ob.get("tag", "").lower()
        if prot in proxy_protocols or tag == "proxy":
            return ob
    obs = config.get("outbounds", [])
    return obs[0] if obs else {}


def _standard_json_wrapper(
    protocol: str, outbound_settings: dict, stream_settings: dict, remarks: str
) -> dict:
    return {
        "log": {"access": "", "error": "", "loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
                "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "0.0.0.0",
                "protocol": "http",
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls"],
                    "routeOnly": False,
                },
                "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
            },
        ],
        "outbounds": [
            {
                "protocol": protocol,
                "tag": "proxy",
                "settings": outbound_settings,
                "streamSettings": stream_settings,
            }
        ],
        "dns": {"servers": ["1.1.1.1", "8.8.8.8"]},
        "routing": {"domainStrategy": "AsIs", "rules": []},
        "remarks": remarks,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  JSON → URI
# ─────────────────────────────────────────────────────────────────────────────
def _stream_to_params(stream: dict) -> dict:
    net = _norm_net(stream.get("network", "tcp"))
    security = stream.get("security", "none")
    params = {"type": net, "headerType": "none"}

    if security and security not in ("none", ""):
        params["security"] = security

    if security == "tls":
        tls = stream.get("tlsSettings") or {}
        if tls.get("serverName"):
            params["sni"] = tls["serverName"]
        if tls.get("fingerprint"):
            params["fp"] = tls["fingerprint"]
        if tls.get("alpn"):
            params["alpn"] = ",".join(tls["alpn"])
        if tls.get("allowInsecure"):
            params["allowInsecure"] = "1"
    elif security == "reality":
        r = stream.get("realitySettings") or {}
        if r.get("serverName"):
            params["sni"] = r["serverName"]
        if r.get("fingerprint"):
            params["fp"] = r["fingerprint"]
        if r.get("publicKey"):
            params["pbk"] = r["publicKey"]
        if r.get("shortId"):
            params["sid"] = r["shortId"]
        if r.get("spiderX"):
            params["spx"] = r["spiderX"]

    if net == "ws":
        ws = stream.get("wsSettings") or {}
        path = ws.get("path", "")
        host = ws.get("host", "") or (ws.get("headers") or {}).get("Host", "")
        if path:
            params["path"] = path
        if host:
            params["host"] = host
    elif net in ("h2", "http"):
        h2 = stream.get("httpSettings") or stream.get("h2Settings") or {}
        path = h2.get("path", "")
        hosts = h2.get("host", [])
        if isinstance(hosts, list):
            hosts = ",".join(hosts)
        if path:
            params["path"] = path
        if hosts:
            params["host"] = hosts
        params["type"] = "h2"
    elif net == "grpc":
        grpc = stream.get("grpcSettings") or {}
        svc = grpc.get("serviceName", "")
        if svc:
            params["serviceName"] = svc
        if grpc.get("multiMode"):
            params["mode"] = "multi"
    elif net == "xhttp":
        xh = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
        path = xh.get("path", "")
        host = xh.get("host", "")
        mode = xh.get("mode", "")
        if path:
            params["path"] = path
        if host:
            params["host"] = host
        if mode:
            params["mode"] = mode
    elif net == "httpupgrade":
        hup = stream.get("httpupgradeSettings") or {}
        path = hup.get("path", "")
        host = hup.get("host", "")
        if path:
            params["path"] = path
        if host:
            params["host"] = host
    elif net in ("tcp", "raw"):
        tcp = stream.get("tcpSettings") or stream.get("rawSettings") or {}
        hdr = tcp.get("header", {})
        htyp = hdr.get("type", "none")
        params["headerType"] = htyp
        params["type"] = "tcp"
        if htyp == "http":
            req = hdr.get("request", {})
            paths = req.get("path", [])
            if isinstance(paths, list) and paths:
                params["path"] = paths[0]
            elif isinstance(paths, str) and paths:
                params["path"] = paths
            hdrs = req.get("headers", {})
            hhost = hdrs.get("Host", "")
            if isinstance(hhost, list) and hhost:
                hhost = hhost[0]
            if hhost:
                params["host"] = hhost
    elif net in ("kcp", "mkcp"):
        kcp = stream.get("kcpSettings") or {}
        hdr = kcp.get("header", {})
        params["headerType"] = hdr.get("type", "none")
        params["type"] = "kcp"
        if kcp.get("seed"):
            params["seed"] = kcp["seed"]
    elif net == "quic":
        quic = stream.get("quicSettings") or {}
        if quic.get("security"):
            params["quicSecurity"] = quic["security"]
        if quic.get("key"):
            params["key"] = quic["key"]
        hdr = quic.get("header", {})
        params["headerType"] = hdr.get("type", "none")

    return params


def vless_outbound_to_uri(outbound: dict, remarks: str = "") -> str:
    settings = outbound.get("settings", {})
    vnext = (settings.get("vnext") or [{}])[0]
    address = vnext.get("address", "")
    port = vnext.get("port", 443)
    user = (vnext.get("users") or [{}])[0]
    uuid = user.get("id", "")
    encryption = user.get("encryption", "none")
    flow = user.get("flow", "")
    stream = outbound.get("streamSettings", {})
    params = _stream_to_params(stream)
    params["encryption"] = encryption
    if flow:
        params["flow"] = flow
    query = _build_query(params)
    fragment = _pct(remarks or outbound.get("tag", "proxy"))
    return f"vless://{uuid}@{address}:{port}?{query}#{fragment}"


def vmess_outbound_to_uri(outbound: dict, remarks: str = "") -> str:
    settings = outbound.get("settings", {})
    vnext = (settings.get("vnext") or [{}])[0]
    address = vnext.get("address", "")
    port = vnext.get("port", 443)
    user = (vnext.get("users") or [{}])[0]
    uuid = user.get("id", "")
    alter_id = user.get("alterId", 0)
    sec = user.get("security", "auto")
    stream = outbound.get("streamSettings", {})
    net = _norm_net(stream.get("network", "tcp"))
    tls_on = stream.get("security", "") == "tls"
    tls = stream.get("tlsSettings") or {}
    obj = {
        "v": "2",
        "ps": remarks,
        "add": address,
        "port": str(port),
        "id": uuid,
        "aid": str(alter_id),
        "scy": sec,
        "net": net,
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if tls_on else "",
        "sni": tls.get("serverName", ""),
        "alpn": ",".join(tls.get("alpn", [])),
        "fp": tls.get("fingerprint", ""),
    }
    if net == "ws":
        ws = stream.get("wsSettings") or {}
        obj["path"] = ws.get("path", "/")
        obj["host"] = ws.get("host", "") or (ws.get("headers") or {}).get("Host", "")
    elif net in ("h2", "http"):
        h2 = stream.get("httpSettings") or {}
        obj["path"] = h2.get("path", "/")
        hosts = h2.get("host", [])
        obj["host"] = hosts[0] if hosts else ""
        obj["net"] = "h2"
    elif net == "grpc":
        grpc = stream.get("grpcSettings") or {}
        obj["path"] = grpc.get("serviceName", "")
        obj["type"] = "gun"
    elif net in ("tcp", "raw"):
        tcp = stream.get("tcpSettings") or stream.get("rawSettings") or {}
        obj["type"] = tcp.get("header", {}).get("type", "none")
    vmess_json = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.b64encode(vmess_json.encode()).decode()
    return f"vmess://{encoded}"


def trojan_outbound_to_uri(outbound: dict, remarks: str = "") -> str:
    settings = outbound.get("settings", {})
    srv = (settings.get("servers") or [{}])[0]
    address = srv.get("address", "")
    port = srv.get("port", 443)
    password = srv.get("password", "")
    stream = outbound.get("streamSettings", {})
    params = _stream_to_params(stream)
    params.pop("encryption", None)
    query = _build_query(params)
    fragment = _pct(remarks or outbound.get("tag", "trojan"))
    return f"trojan://{password}@{address}:{port}?{query}#{fragment}"


def shadowsocks_outbound_to_uri(outbound: dict, remarks: str = "") -> str:
    settings = outbound.get("settings", {})
    srv = (settings.get("servers") or [{}])[0]
    address = srv.get("address", "")
    port = srv.get("port", 8388)
    method = srv.get("method", "aes-256-gcm")
    password = srv.get("password", "")
    userinfo = base64.b64encode(f"{method}:{password}".encode()).decode()
    fragment = _pct(remarks or "")
    return f"ss://{userinfo}@{address}:{port}#{fragment}"


def json_to_uri(config: dict) -> str:
    ob = _find_proxy_outbound(config)
    remarks = config.get("remarks", "") or ob.get("tag", "")
    protocol = ob.get("protocol", "").lower()
    if protocol == "vless":
        return vless_outbound_to_uri(ob, remarks)
    elif protocol == "vmess":
        return vmess_outbound_to_uri(ob, remarks)
    elif protocol == "trojan":
        return trojan_outbound_to_uri(ob, remarks)
    elif protocol in ("shadowsocks", "ss"):
        return shadowsocks_outbound_to_uri(ob, remarks)
    else:
        raise ValueError(f"Unsupported protocol for URI conversion: {protocol!r}")


# ─────────────────────────────────────────────────────────────────────────────
#  URI → JSON
# ─────────────────────────────────────────────────────────────────────────────
def _params_to_stream(params: dict) -> dict:
    net = _norm_net(params.get("type", "tcp"))
    security = params.get("security", "none")
    stream = {"network": net}

    if security and security not in ("none", ""):
        stream["security"] = security

    if security == "tls":
        tls = {}
        sni = params.get("sni", "")
        fp = params.get("fp", "")
        alpn = params.get("alpn", "")
        ai = params.get("allowInsecure", "")
        if sni:
            tls["serverName"] = sni
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = [a.strip() for a in alpn.split(",")]
        if ai == "1":
            tls["allowInsecure"] = True
        if tls:
            stream["tlsSettings"] = tls
    elif security == "reality":
        r = {}
        if params.get("sni"):
            r["serverName"] = params["sni"]
        if params.get("fp"):
            r["fingerprint"] = params["fp"]
        if params.get("pbk"):
            r["publicKey"] = params["pbk"]
        if params.get("sid"):
            r["shortId"] = params["sid"]
        if params.get("spx"):
            r["spiderX"] = params["spx"]
        if r:
            stream["realitySettings"] = r

    if net == "ws":
        ws = {}
        if params.get("path"):
            ws["path"] = params["path"]
        if params.get("host"):
            ws["host"] = params["host"]
        if ws:
            stream["wsSettings"] = ws
    elif net in ("h2", "http"):
        h2 = {}
        if params.get("path"):
            h2["path"] = params["path"]
        if params.get("host"):
            h2["host"] = [h.strip() for h in params["host"].split(",")]
        stream["httpSettings"] = h2
        stream["network"] = "h2"
    elif net == "grpc":
        grpc = {}
        if params.get("serviceName"):
            grpc["serviceName"] = params["serviceName"]
        if params.get("mode") == "multi":
            grpc["multiMode"] = True
        if grpc:
            stream["grpcSettings"] = grpc
    elif net == "xhttp":
        xh = {}
        if params.get("path"):
            xh["path"] = params["path"]
        if params.get("host"):
            xh["host"] = params["host"]
        if params.get("mode"):
            xh["mode"] = params["mode"]
        if xh:
            stream["xhttpSettings"] = xh
    elif net == "httpupgrade":
        hup = {}
        if params.get("path"):
            hup["path"] = params["path"]
        if params.get("host"):
            hup["host"] = params["host"]
        if hup:
            stream["httpupgradeSettings"] = hup
    elif net in ("tcp", "raw"):
        htyp = params.get("headerType", "none")
        tcp = {"header": {"type": htyp}}
        if htyp == "http":
            req = {}
            if params.get("path"):
                req["path"] = [params["path"]]
            if params.get("host"):
                req["headers"] = {"Host": [params["host"]]}
            tcp["header"]["request"] = req
        stream["tcpSettings"] = tcp
        stream["network"] = "tcp"
    elif net in ("kcp", "mkcp"):
        kcp = {"header": {"type": params.get("headerType", "none")}}
        if params.get("seed"):
            kcp["seed"] = params["seed"]
        stream["kcpSettings"] = kcp
        stream["network"] = "kcp"
    elif net == "quic":
        quic = {"header": {"type": params.get("headerType", "none")}}
        if params.get("quicSecurity"):
            quic["security"] = params["quicSecurity"]
        if params.get("key"):
            quic["key"] = params["key"]
        stream["quicSettings"] = quic

    return stream


def vless_uri_to_json(uri: str) -> dict:
    parsed = urlparse(uri)
    uuid = parsed.username or ""
    address = parsed.hostname or ""
    port = parsed.port or 443
    params = _parse_query(parsed.query) if parsed.query else {}
    remarks = unquote(parsed.fragment) if parsed.fragment else ""
    encryption = params.get("encryption", "none")
    flow = params.get("flow", "")
    user = {"id": uuid, "encryption": encryption}
    if flow:
        user["flow"] = flow
    outbound_settings = {"vnext": [{"address": address, "port": port, "users": [user]}]}
    stream = _params_to_stream(params)
    return _standard_json_wrapper("vless", outbound_settings, stream, remarks)


def vmess_uri_to_json(uri: str) -> dict:
    encoded = uri[len("vmess://") :].split("#")[0]
    encoded += "=" * (-len(encoded) % 4)
    try:
        vmess = json.loads(base64.b64decode(encoded).decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Cannot decode VMess URI: {e}")
    address = vmess.get("add", "")
    port = int(vmess.get("port", 443))
    uuid = vmess.get("id", "")
    alter_id = int(vmess.get("aid", 0))
    sec = vmess.get("scy", vmess.get("security", "auto"))
    net = _norm_net(vmess.get("net", "tcp"))
    tls_on = vmess.get("tls", "") == "tls"
    remarks = vmess.get("ps", "")
    user = {"id": uuid, "alterId": alter_id, "security": sec}
    outbound_settings = {"vnext": [{"address": address, "port": port, "users": [user]}]}
    stream = {"network": net}
    if tls_on:
        stream["security"] = "tls"
        tls = {}
        if vmess.get("sni"):
            tls["serverName"] = vmess["sni"]
        if vmess.get("fp"):
            tls["fingerprint"] = vmess["fp"]
        if vmess.get("alpn"):
            tls["alpn"] = [a.strip() for a in vmess["alpn"].split(",")]
        if tls:
            stream["tlsSettings"] = tls
    if net == "ws":
        ws = {}
        if vmess.get("path"):
            ws["path"] = vmess["path"]
        if vmess.get("host"):
            ws["host"] = vmess["host"]
        if ws:
            stream["wsSettings"] = ws
    elif net in ("h2", "http"):
        h2 = {}
        if vmess.get("path"):
            h2["path"] = vmess["path"]
        if vmess.get("host"):
            h2["host"] = [vmess["host"]]
        stream["httpSettings"] = h2
        stream["network"] = "h2"
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": vmess.get("path", "")}
    elif net in ("tcp", "raw"):
        htyp = vmess.get("type", "none")
        stream["tcpSettings"] = {"header": {"type": htyp}}
        stream["network"] = "tcp"
    return _standard_json_wrapper("vmess", outbound_settings, stream, remarks)


def trojan_uri_to_json(uri: str) -> dict:
    parsed = urlparse(uri)
    password = parsed.username or ""
    address = parsed.hostname or ""
    port = parsed.port or 443
    params = _parse_query(parsed.query) if parsed.query else {}
    remarks = unquote(parsed.fragment) if parsed.fragment else ""
    outbound_settings = {
        "servers": [{"address": address, "port": port, "password": password}]
    }
    stream = _params_to_stream(params)
    return _standard_json_wrapper("trojan", outbound_settings, stream, remarks)


def ss_uri_to_json(uri: str) -> dict:
    raw = uri[len("ss://") :]
    remarks = ""
    if "#" in raw:
        raw, frag = raw.rsplit("#", 1)
        remarks = unquote(frag)
    if "@" in raw:
        b64_part, hostinfo = raw.rsplit("@", 1)
        b64_part += "=" * (-len(b64_part) % 4)
        try:
            decoded = base64.b64decode(b64_part).decode("utf-8")
            method, password = decoded.split(":", 1)
        except Exception:
            method = b64_part
            password = ""
        if ":" in hostinfo:
            address, port_str = hostinfo.rsplit(":", 1)
            port = int(port_str)
        else:
            address, port = hostinfo, 8388
    else:
        raw += "=" * (-len(raw) % 4)
        decoded = base64.b64decode(raw).decode("utf-8")
        userinfo, hostinfo = decoded.rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        address, port_str = hostinfo.rsplit(":", 1)
        port = int(port_str)
    outbound_settings = {
        "servers": [
            {"address": address, "port": port, "method": method, "password": password}
        ]
    }
    return _standard_json_wrapper(
        "shadowsocks", outbound_settings, {"network": "tcp"}, remarks
    )


def uri_to_json(uri: str) -> dict:
    uri = uri.strip()
    if uri.startswith("vless://"):
        return vless_uri_to_json(uri)
    elif uri.startswith("vmess://"):
        return vmess_uri_to_json(uri)
    elif uri.startswith("trojan://"):
        return trojan_uri_to_json(uri)
    elif uri.startswith("ss://"):
        return ss_uri_to_json(uri)
    else:
        raise ValueError(f"Unrecognised URI scheme: {uri[:30]!r}")


def _split_json_blocks(text: str):
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                yield text[start : i + 1]
                start = None


def process_text(text: str, direction: str = "auto") -> list:
    """
    Process raw text and return a list of (input_hint, result_str) tuples.
    direction: "auto" | "to_uri" | "to_json"
    """
    text = _fix_surrogate_pairs(text.strip())
    results = []

    def _try_json_block(block):
        try:
            cfg = json.loads(block)
        except json.JSONDecodeError as e:
            return None, f"[JSON parse error] {e}"
        try:
            return json_to_uri(cfg), None
        except Exception as e:
            return None, f"[Conversion error] {e}"

    def _try_uri(line):
        try:
            cfg = uri_to_json(line)
            return json.dumps(cfg, ensure_ascii=False, indent=2), None
        except Exception as e:
            return None, f"[Conversion error] {e}"

    stripped = text.lstrip()
    if direction == "to_json" or (
        direction == "auto"
        and any(
            stripped.startswith(p)
            for p in ("vless://", "vmess://", "trojan://", "ss://")
        )
    ):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(
                line.startswith(p)
                for p in ("vless://", "vmess://", "trojan://", "ss://")
            ):
                out, err = _try_uri(line)
                results.append((line[:60] + "…", out or f"# ERROR: {err}"))

    elif direction == "to_uri" or (direction == "auto" and stripped.startswith("{")):
        for block in _split_json_blocks(text):
            out, err = _try_json_block(block)
            results.append(
                (block[:40].replace("\n", " ") + "…", out or f"# ERROR: {err}")
            )
    else:
        uri_lines = [
            l.strip()
            for l in text.splitlines()
            if l.strip()
            and any(
                l.strip().startswith(p)
                for p in ("vless://", "vmess://", "trojan://", "ss://")
            )
        ]
        json_blocks = list(_split_json_blocks(text))
        for line in uri_lines:
            out, err = _try_uri(line)
            results.append((line[:60] + "…", out or f"# ERROR: {err}"))
        for block in json_blocks:
            out, err = _try_json_block(block)
            results.append(
                (block[:40].replace("\n", " ") + "…", out or f"# ERROR: {err}")
            )
    return results


# ══════════════════════════════════════════════════════════════════════════════
#  THEME MANAGER
# ══════════════════════════════════════════════════════════════════════════════
class ThemeManager:
    """
    Manages light and dark themes.
    Accent colour: sky-blue / electric-blue — distinct from the teal (#00D4AA)
    used by ReplaceCharacter and the cyan (#00E5FF) used by CryptoGraphy.
    """

    current: str = "light"

    DARK = """
QMainWindow, QWidget {
    background-color: #0D0F14; color: #E8EAFF;
    font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
}
QScrollBar:vertical { background: #131720; width: 8px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #2A3050; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #00CFFF; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #131720; height: 8px; border-radius: 4px; }
QScrollBar::handle:horizontal { background: #2A3050; border-radius: 4px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #00CFFF; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QPushButton {
    background-color: #1E2436; color: #E8EAFF;
    border: 1px solid #2A3050; padding: 7px 16px;
    border-radius: 6px; font-weight: 600; font-size: 12px;
}
QPushButton:hover { background-color: #2A3050; border-color: #00CFFF; color: #00CFFF; }
QPushButton:pressed { background-color: #00CFFF; color: #0D0F14; }
QPushButton:disabled { background-color: #131720; color: #2A3050; border-color: #1A1F2E; }
QPushButton#accent {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                                stop:0 #00CFFF, stop:1 #8055FF);
    color: #0D0F14; border: none; font-size: 13px; font-weight: 700;
    padding: 10px 24px;
}
QPushButton#accent:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                                stop:0 #22DFFF, stop:1 #9975FF);
    color: #0D0F14;
}
QPushButton#accent:disabled { background: #1E2436; color: #3A4060; border: none; }
QPushButton#danger { background-color: transparent; color: #FF3860; border: 1px solid #FF3860; }
QPushButton#danger:hover { background-color: #FF3860; color: #ffffff; }
QLineEdit, QTextEdit {
    background-color: #131720; color: #E8EAFF;
    border: 1px solid #2A3050; border-radius: 6px;
    padding: 6px 10px; font-size: 12px;
    selection-background-color: #00CFFF; selection-color: #0D0F14;
}
QLineEdit:focus, QTextEdit:focus { border-color: #00CFFF; background-color: #161B2A; }
QLineEdit:disabled { background-color: #0F1018; color: #3A4060; border-color: #1A1F2E; }
QRadioButton { color: #E8EAFF; spacing: 8px; font-size: 12px; }
QRadioButton::indicator {
    width: 15px; height: 15px; border: 1px solid #2A3050;
    border-radius: 8px; background: #131720;
}
QRadioButton::indicator:checked { background: #00CFFF; border-color: #00CFFF; }
QGroupBox {
    border: 1px solid #2A3050; border-radius: 6px;
    margin-top: 10px; padding-top: 6px;
    font-size: 11px; font-weight: 700; color: #6B7299; letter-spacing: 1px;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 10px;
    background-color: #0D0F14; padding: 0 4px; color: #00CFFF;
}
QMenuBar { background-color: #0D0F14; color: #E8EAFF; border-bottom: 1px solid #1A1F2E; }
QMenuBar::item:selected { background-color: #1E2436; color: #00CFFF; }
QMenu { background-color: #131720; color: #E8EAFF; border: 1px solid #2A3050; }
QMenu::item:selected { background-color: #1E2436; color: #00CFFF; }
QStatusBar { background-color: #0A0C10; color: #3D4466; font-size: 11px; border-top: 1px solid #1A1F2E; }
"""

    LIGHT = """
QMainWindow, QWidget {
    background-color: #F0F4F8; color: #1A2030;
    font-family: 'Segoe UI', 'SF Pro Display', sans-serif;
}
QScrollBar:vertical { background: #E0E6EE; width: 8px; border-radius: 4px; }
QScrollBar::handle:vertical { background: #B0BED8; border-radius: 4px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #0088BB; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal { background: #E0E6EE; height: 8px; border-radius: 4px; }
QScrollBar::handle:horizontal { background: #B0BED8; border-radius: 4px; min-width: 30px; }
QScrollBar::handle:horizontal:hover { background: #0088BB; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QPushButton {
    background-color: #FFFFFF; color: #1A2030;
    border: 1px solid #C8D5E0; padding: 7px 16px;
    border-radius: 6px; font-weight: 600; font-size: 12px;
}
QPushButton:hover { background-color: #E8F0F8; border-color: #0088BB; color: #0088BB; }
QPushButton:pressed { background-color: #0088BB; color: #FFFFFF; }
QPushButton:disabled { background-color: #EEF0F4; color: #A0AABB; border-color: #D0D8E0; }
QPushButton#accent {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                                stop:0 #0099CC, stop:1 #6644BB);
    color: #FFFFFF; border: none; font-size: 13px; font-weight: 700;
    padding: 10px 24px;
}
QPushButton#accent:hover {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                                stop:0 #00AADD, stop:1 #7754CC);
}
QPushButton#accent:disabled { background: #E0E8F0; color: #A0B0C0; border: none; }
QPushButton#danger { background-color: transparent; color: #CC2244; border: 1px solid #CC2244; }
QPushButton#danger:hover { background-color: #CC2244; color: #ffffff; }
QLineEdit, QTextEdit {
    background-color: #FFFFFF; color: #1A2030;
    border: 1px solid #C8D5E0; border-radius: 6px;
    padding: 6px 10px; font-size: 12px;
    selection-background-color: #0099CC; selection-color: #FFFFFF;
}
QLineEdit:focus, QTextEdit:focus { border-color: #0099CC; background-color: #F8FBFF; }
QLineEdit:disabled { background-color: #F4F6F8; color: #A0AABB; border-color: #D8DEE8; }
QRadioButton { color: #1A2030; spacing: 8px; font-size: 12px; }
QRadioButton::indicator {
    width: 15px; height: 15px; border: 1px solid #C8D5E0;
    border-radius: 8px; background: #FFFFFF;
}
QRadioButton::indicator:checked { background: #0099CC; border-color: #0099CC; }
QGroupBox {
    border: 1px solid #C8D5E0; border-radius: 6px;
    margin-top: 10px; padding-top: 6px;
    font-size: 11px; font-weight: 700; color: #6B7A99; letter-spacing: 1px;
}
QGroupBox::title {
    subcontrol-origin: margin; left: 10px;
    background-color: #F0F4F8; padding: 0 4px; color: #0099CC;
}
QMenuBar { background-color: #F0F4F8; color: #1A2030; border-bottom: 1px solid #D0D8E4; }
QMenuBar::item:selected { background-color: #E0EEF8; color: #0099CC; }
QMenu { background-color: #FFFFFF; color: #1A2030; border: 1px solid #C8D5E0; }
QMenu::item:selected { background-color: #E0EEF8; color: #0099CC; }
QStatusBar { background-color: #E8EDF4; color: #6B7A99; font-size: 11px; border-top: 1px solid #C8D5E0; }
"""

    @classmethod
    def apply(cls, app: QApplication, theme: str):
        cls.current = theme
        app.setStyleSheet(cls.DARK if theme == "dark" else cls.LIGHT)

    @classmethod
    def is_dark(cls) -> bool:
        return cls.current == "dark"

    @classmethod
    def accent_color(cls) -> str:
        return "#00CFFF" if cls.is_dark() else "#0099CC"

    @classmethod
    def success_color(cls) -> str:
        return "#00EE99" if cls.is_dark() else "#007755"

    @classmethod
    def danger_color(cls) -> str:
        return "#FF3860" if cls.is_dark() else "#CC2244"

    @classmethod
    def warning_color(cls) -> str:
        return "#FFB300" if cls.is_dark() else "#AA7700"

    @classmethod
    def dim_color(cls) -> str:
        return "#6B7299" if cls.is_dark() else "#6B7A99"


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG MANAGER  — saves user preferences to JSON
# ══════════════════════════════════════════════════════════════════════════════
class ConfigManager:
    DEFAULTS: Dict = {
        "theme": "light",
        "direction": "auto",  # "auto" | "to_json" | "to_uri"
    }

    def __init__(self):
        script_dir = Path(sys.argv[0]).parent
        self._path = script_dir / CONFIG_FILE
        self._data: Dict = deepcopy(self.DEFAULTS)
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                self._data.update(
                    {k: v for k, v in saved.items() if k in self.DEFAULTS}
                )
            except Exception:
                pass

    def save(self):
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2)
        except Exception:
            pass

    def get(self, key: str):
        return self._data.get(key, self.DEFAULTS.get(key))

    def set(self, key: str, value):
        self._data[key] = value


# ══════════════════════════════════════════════════════════════════════════════
#  LOG PANEL
# ══════════════════════════════════════════════════════════════════════════════
class LogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        hdr = QHBoxLayout()
        lbl = QLabel("  OPERATION LOG")
        lbl.setStyleSheet(
            "color: #6B7299; font-size: 11px; font-weight: 700; letter-spacing: 1px;"
        )
        save_btn = QPushButton("💾  Save Log")
        save_btn.setFixedHeight(28)
        save_btn.clicked.connect(self._save_log)
        clr = QPushButton("Clear")
        clr.setFixedHeight(28)
        clr.clicked.connect(self.clear)
        hdr.addWidget(lbl)
        hdr.addStretch()
        hdr.addWidget(save_btn)
        hdr.addWidget(clr)
        layout.addLayout(hdr)

        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet(
            "QTextEdit { border: 1px solid #2A3050; border-radius: 6px; "
            "font-family: Consolas, 'Courier New', monospace; "
            "font-size: 11px; padding: 8px; }"
        )
        layout.addWidget(self.log)

    def add(self, message: str, level: str = "INFO"):
        ts = QDateTime.currentDateTime().toString("HH:mm:ss")
        dark = ThemeManager.is_dark()
        colors = {
            "INFO": "#6B7299" if dark else "#6B7A99",
            "SUCCESS": "#00EE99" if dark else "#007755",
            "ERROR": "#FF3860" if dark else "#CC2244",
            "WARNING": "#FFB300" if dark else "#AA7700",
        }
        ts_color = "#2A3050" if dark else "#A0AACC"
        color = colors.get(level, colors["INFO"])
        self.log.append(
            f'<span style="color:{ts_color}">[{ts}]</span> '
            f'<span style="color:{color}">{message}</span>'
        )
        self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())

    def clear(self):
        self.log.clear()

    def _save_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log File",
            str(Path.home() / "v2ray_converter.log"),
            "Log Files (*.log);;Text Files (*.txt);;All Files (*)",
        )
        if path:
            try:
                plain = re.sub(r"<[^>]+>", "", self.log.toHtml())
                plain = re.sub(r"&amp;", "&", plain)
                plain = re.sub(r"&lt;", "<", plain)
                plain = re.sub(r"&gt;", ">", plain)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(plain)
                QMessageBox.information(self, "Saved", f"Log saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not save log:\n{e}")


# ══════════════════════════════════════════════════════════════════════════════
#  ACTIVITY INDICATOR
# ══════════════════════════════════════════════════════════════════════════════
class ActivityIndicator(QLabel):
    _DOTS = ["", ".", "..", "..."]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._base = "Ready"
        self._dot_i = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self.setText("Ready")
        self._set_style("dim")

    def start(self, operation: str):
        self._base = operation
        self._dot_i = 0
        self._timer.start(350)
        self._tick()

    def stop(self):
        self._timer.stop()
        self.setText("✔  Ready")
        self._set_style("ok")

    def _tick(self):
        dots = self._DOTS[self._dot_i % len(self._DOTS)]
        self.setText(f"⚙  {self._base}{dots}")
        self._set_style("active")
        self._dot_i += 1

    def _set_style(self, mode: str):
        colors = {
            "dim": ThemeManager.dim_color(),
            "ok": ThemeManager.success_color(),
            "active": ThemeManager.accent_color(),
        }
        self.setStyleSheet(
            f"color: {colors.get(mode, '#6B7299')}; "
            "font-size: 12px; font-weight: 600;"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  CONVERT WORKER  — runs process_text() off the main thread
# ══════════════════════════════════════════════════════════════════════════════
class ConvertWorker(QThread):
    results_ready = pyqtSignal(list)  # list[tuple[str, str]]
    log_msg = pyqtSignal(str, str)
    finished = pyqtSignal(bool)

    def __init__(self, text: str, direction: str, parent=None):
        super().__init__(parent)
        self.text = text
        self.direction = direction

    def run(self):
        try:
            self.log_msg.emit("Starting conversion…", "INFO")
            results = process_text(self.text, self.direction)

            if not results:
                self.log_msg.emit("No convertible content found in input.", "WARNING")
            else:
                ok = sum(1 for _, r in results if not r.startswith("# ERROR:"))
                err = len(results) - ok
                for hint, result in results:
                    if result.startswith("# ERROR:"):
                        self.log_msg.emit(f"✘  {hint}", "ERROR")
                    else:
                        self.log_msg.emit(f"✔  {hint}", "SUCCESS")
                summary = f"Done — {ok} converted"
                if err:
                    summary += f", {err} error(s)"
                level = "SUCCESS" if err == 0 else "WARNING"
                self.log_msg.emit(summary, level)

            self.results_ready.emit(results)
            self.finished.emit(True)
        except Exception as e:
            self.log_msg.emit(f"Fatal error: {e}", "ERROR")
            self.results_ready.emit([])
            self.finished.emit(False)


# ══════════════════════════════════════════════════════════════════════════════
#  ABOUT DIALOG
# ══════════════════════════════════════════════════════════════════════════════
class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(520, 500)

        root = QVBoxLayout(self)
        root.setSpacing(0)
        root.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

        hero = QLabel("V2RAY CONVERTER")
        hero.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hero.setStyleSheet(
            f"color: {ThemeManager.accent_color()}; font-size: 22px; font-weight: 900; "
            "letter-spacing: 8px; font-family: 'Consolas', monospace; "
            "padding: 12px 0 4px 0;"
        )
        layout.addWidget(hero)

        ver_lbl = QLabel(f"v{APP_VERSION}  ·  V2Ray / Xray  URI ↔ JSON Converter")
        ver_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        ver_lbl.setStyleSheet("color: #6B7299; font-size: 12px; letter-spacing: 2px;")
        layout.addWidget(ver_lbl)

        sep = QFrame()
        sep.setFixedHeight(2)
        sep.setStyleSheet(
            f"background: qlineargradient(x1:0,y1:0,x2:1,y2:0, "
            f"stop:0 transparent, stop:0.3 {ThemeManager.accent_color()}, "
            f"stop:0.7 #8055FF, stop:1 transparent);"
        )
        layout.addWidget(sep)

        sections = [
            (
                "🔄  WHAT IT DOES",
                "Bidirectional converter between V2Ray / Xray full JSON configuration "
                "files and compact share-link proxy URIs. Paste one config or dozens — "
                "all are converted in a single click.",
            ),
            (
                "📡  SUPPORTED PROTOCOLS",
                "<b>VLESS</b> · <b>VMess</b> · <b>Trojan</b> · <b>Shadowsocks</b><br>"
                "Transport layers: <code>ws</code>, <code>tcp/raw</code>, "
                "<code>xhttp/splithttp</code>, <code>h2</code>, <code>grpc</code>, "
                "<code>httpupgrade</code>, <code>kcp/mkcp</code>, <code>quic</code><br>"
                "Security modes: <code>tls</code> (with SNI, ALPN, fingerprint), "
                "<code>reality</code> (pbk/sid/spx), <code>none</code>",
            ),
            (
                "⚙  CONVERSION DIRECTION",
                "<b>Auto-detect</b> — Inspects the first characters of your input and "
                "routes automatically. URIs that start with <code>vless://</code> / "
                "<code>vmess://</code> etc. go to JSON; objects starting with "
                "<code>{</code> go to URI.<br>"
                "<b>URI → JSON</b> — Forces every line to be parsed as a proxy share link.<br>"
                "<b>JSON → URI</b> — Forces every JSON block to produce a URI.",
            ),
            (
                "📦  BATCH PROCESSING",
                "Paste multiple proxy URIs (one per line) <em>or</em> multiple JSON "
                "blocks in a single operation. Each result is labelled with a comment "
                "line showing its source. Mixed files (URIs and JSON together) are "
                "handled automatically in Auto-detect mode.",
            ),
            (
                "↑  USE AS INPUT",
                "The <b>Use as Input</b> button moves the current output back into "
                "the input area so you can chain conversions — for example: convert a "
                "URI to JSON, tweak the JSON, then convert back to a URI.",
            ),
            (
                "👤  CREATOR",
                "Built with <b>Python</b> and <b>PyQt6</b>.  "
                "Created by @Sparky2273 — DM on Telegram for support.",
            ),
        ]

        for title, body in sections:
            lbl = QLabel(title)
            lbl.setStyleSheet(
                f"color: {ThemeManager.accent_color()}; font-size: 13px; "
                "font-weight: 800; letter-spacing: 1px; padding-top: 4px;"
            )
            layout.addWidget(lbl)
            txt = QLabel(body)
            txt.setWordWrap(True)
            txt.setTextFormat(Qt.TextFormat.RichText)
            txt.setStyleSheet(
                "color: #A0A8CC; font-size: 12px; line-height: 160%; "
                "padding-left: 4px;"
            )
            layout.addWidget(txt)

        layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.setObjectName("accent")
        close_btn.setFixedHeight(36)
        close_btn.clicked.connect(self.accept)
        root.addWidget(close_btn)
        root.setContentsMargins(12, 0, 12, 12)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._worker: Optional[ConvertWorker] = None
        self._config = ConfigManager()
        self._build_ui()
        self._build_menu()
        self._load_config()
        self.setAcceptDrops(True)

    # ── UI BUILD ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.setMinimumSize(900, 600)
        self.resize(1120, 740)

        self._status_bar = QStatusBar()
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("Ready")

        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(16, 12, 16, 12)
        root_layout.setSpacing(10)
        self.setCentralWidget(root)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = QHBoxLayout()

        self._title_lbl = QLabel("V2RAY CONVERTER")
        self._title_lbl.setStyleSheet(
            f"color: {ThemeManager.accent_color()}; font-size: 20px; "
            "font-weight: 900; letter-spacing: 6px; "
            "font-family: 'Consolas', monospace;"
        )
        sub_lbl = QLabel(f"URI ↔ JSON Converter  v{APP_VERSION}")
        sub_lbl.setStyleSheet(
            f"color: {ThemeManager.dim_color()}; font-size: 11px; "
            "letter-spacing: 2px;"
        )
        sub_lbl.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self._theme_btn = QPushButton("🌙  Dark Mode")
        self._theme_btn.setFixedHeight(30)
        self._theme_btn.setToolTip("Toggle between Light and Dark themes")
        self._theme_btn.clicked.connect(self._toggle_theme)

        about_btn = QPushButton("ℹ  About")
        about_btn.setFixedHeight(30)
        about_btn.clicked.connect(self._open_about)

        hdr.addWidget(self._title_lbl)
        hdr.addWidget(sub_lbl)
        hdr.addStretch()
        hdr.addWidget(self._theme_btn)
        hdr.addWidget(about_btn)
        root_layout.addLayout(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("background: #1A1F2E; max-height: 1px;")
        root_layout.addWidget(sep)

        # ── Main horizontal splitter ──────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1A1F2E; width: 2px; }")
        root_layout.addWidget(splitter, 1)

        # ── Left panel ────────────────────────────────────────────────────────
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 8, 0)
        left_layout.setSpacing(8)

        # ── INPUT GROUP ───────────────────────────────────────────────────────
        input_grp = QGroupBox("INPUT  —  Paste JSON config or proxy URI(s)")
        ig_layout = QVBoxLayout(input_grp)
        ig_layout.setSpacing(6)

        in_btn_row = QHBoxLayout()
        self._load_btn = QPushButton("📂  Load File")
        self._paste_btn = QPushButton("📋  Paste")
        self._sample_btn = QPushButton("💡  Example")
        self._clear_in_btn = QPushButton("🗑  Clear")
        self._clear_in_btn.setObjectName("danger")
        for btn in [
            self._load_btn,
            self._paste_btn,
            self._sample_btn,
            self._clear_in_btn,
        ]:
            btn.setFixedHeight(28)
        self._load_btn.setToolTip("Load a .txt or .json file into the input area")
        self._paste_btn.setToolTip("Paste clipboard content into input")
        self._sample_btn.setToolTip("Insert a sample VLESS URI to test with")
        self._load_btn.clicked.connect(self._load_file)
        self._paste_btn.clicked.connect(self._paste_clipboard)
        self._sample_btn.clicked.connect(self._insert_sample)
        self._clear_in_btn.clicked.connect(self._input_edit_clear)
        in_btn_row.addWidget(self._load_btn)
        in_btn_row.addWidget(self._paste_btn)
        in_btn_row.addWidget(self._sample_btn)
        in_btn_row.addStretch()
        in_btn_row.addWidget(self._clear_in_btn)
        ig_layout.addLayout(in_btn_row)

        self._input_edit = QTextEdit()
        self._input_edit.setFont(QFont("Consolas", 10))
        self._input_edit.setPlaceholderText(
            "Paste a V2Ray JSON config or proxy URI(s) here…\n\n"
            "  Examples:\n"
            "    vless://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            "@host:443?encryption=none&security=tls&type=ws&…\n\n"
            "    vmess://eyJ2IjoiMiIsInBzIjoiTXkgTm9kZSIsImFkZCI6ImV4YW1wbGUuY29tIn0=\n\n"
            '    {"outbounds": [{"protocol": "vless", '
            '"settings": {…}, "streamSettings": {…}}]}'
        )
        self._input_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        ig_layout.addWidget(self._input_edit)
        left_layout.addWidget(input_grp, 3)  # stretch = 3

        # ── DIRECTION GROUP ───────────────────────────────────────────────────
        dir_grp = QGroupBox("CONVERSION DIRECTION")
        dir_layout = QHBoxLayout(dir_grp)
        dir_layout.setSpacing(28)

        self._dir_auto = QRadioButton("🔄  Auto-detect")
        self._dir_to_json = QRadioButton("🔗  URI → JSON")
        self._dir_to_uri = QRadioButton("📄  JSON → URI")
        self._dir_auto.setChecked(True)
        self._dir_auto.setToolTip(
            "Automatically detect whether the input is a URI or JSON"
        )
        self._dir_to_json.setToolTip(
            "Force every input line to be treated as a proxy URI"
        )
        self._dir_to_uri.setToolTip(
            "Force every JSON block in the input to be converted to a URI"
        )

        self._dir_group = QButtonGroup(self)
        self._dir_group.addButton(self._dir_auto, 0)
        self._dir_group.addButton(self._dir_to_json, 1)
        self._dir_group.addButton(self._dir_to_uri, 2)

        dir_layout.addWidget(self._dir_auto)
        dir_layout.addWidget(self._dir_to_json)
        dir_layout.addWidget(self._dir_to_uri)
        dir_layout.addStretch()
        left_layout.addWidget(dir_grp)

        # ── CONVERT BUTTON + ACTIVITY INDICATOR ──────────────────────────────
        ctrl_row = QHBoxLayout()
        self._convert_btn = QPushButton("⚡  Convert")
        self._convert_btn.setObjectName("accent")
        self._convert_btn.setFixedHeight(42)
        self._convert_btn.clicked.connect(self._do_convert)
        self._activity = ActivityIndicator()
        ctrl_row.addWidget(self._convert_btn, 2)
        ctrl_row.addWidget(self._activity, 1)
        left_layout.addLayout(ctrl_row)

        # ── OUTPUT GROUP ──────────────────────────────────────────────────────
        output_grp = QGroupBox("OUTPUT")
        og_layout = QVBoxLayout(output_grp)
        og_layout.setSpacing(6)

        out_btn_row = QHBoxLayout()
        self._stats_lbl = QLabel("")
        self._stats_lbl.setStyleSheet(
            f"color: {ThemeManager.dim_color()}; font-size: 11px;"
        )
        self._use_as_input_btn = QPushButton("↑  Use as Input")
        self._copy_btn = QPushButton("📋  Copy All")
        self._save_btn = QPushButton("💾  Save File")
        self._clear_out_btn = QPushButton("🗑  Clear")
        self._clear_out_btn.setObjectName("danger")
        for btn in [
            self._use_as_input_btn,
            self._copy_btn,
            self._save_btn,
            self._clear_out_btn,
        ]:
            btn.setFixedHeight(28)
        self._use_as_input_btn.setToolTip(
            "Move the output back to the input area for chained conversions"
        )
        self._use_as_input_btn.clicked.connect(self._use_output_as_input)
        self._copy_btn.clicked.connect(self._copy_output)
        self._save_btn.clicked.connect(self._save_output)
        self._clear_out_btn.clicked.connect(self._clear_output)

        out_btn_row.addWidget(self._stats_lbl)
        out_btn_row.addStretch()
        out_btn_row.addWidget(self._use_as_input_btn)
        out_btn_row.addWidget(self._copy_btn)
        out_btn_row.addWidget(self._save_btn)
        out_btn_row.addWidget(self._clear_out_btn)
        og_layout.addLayout(out_btn_row)

        self._output_edit = QTextEdit()
        self._output_edit.setReadOnly(True)
        self._output_edit.setFont(QFont("Consolas", 10))
        self._output_edit.setPlaceholderText("Converted output will appear here…")
        self._output_edit.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        og_layout.addWidget(self._output_edit)
        left_layout.addWidget(output_grp, 3)  # stretch = 3

        splitter.addWidget(left)

        # ── Right panel: log ──────────────────────────────────────────────────
        self._log_panel = LogPanel()
        splitter.addWidget(self._log_panel)
        splitter.setSizes([700, 380])

    # ── MENU BAR ──────────────────────────────────────────────────────────────
    def _build_menu(self):
        menubar = QMenuBar(self)

        # File
        file_menu = QMenu("&File", self)
        act_load = QAction("📂  Load File…", self)
        act_load.setShortcut("Ctrl+O")
        act_load.triggered.connect(self._load_file)
        act_save = QAction("💾  Save Output…", self)
        act_save.setShortcut("Ctrl+S")
        act_save.triggered.connect(self._save_output)
        act_quit = QAction("Quit", self)
        act_quit.setShortcut("Ctrl+Q")
        act_quit.triggered.connect(QApplication.quit)
        file_menu.addAction(act_load)
        file_menu.addAction(act_save)
        file_menu.addSeparator()
        file_menu.addAction(act_quit)
        menubar.addMenu(file_menu)

        # Edit
        edit_menu = QMenu("&Edit", self)
        act_copy = QAction("📋  Copy Output", self)
        act_copy.setShortcut("Ctrl+Shift+C")
        act_copy.triggered.connect(self._copy_output)
        act_swap = QAction("↑  Use Output as Input", self)
        act_swap.triggered.connect(self._use_output_as_input)
        act_clear = QAction("Clear All", self)
        act_clear.triggered.connect(self._clear_all)
        edit_menu.addAction(act_copy)
        edit_menu.addAction(act_swap)
        edit_menu.addSeparator()
        edit_menu.addAction(act_clear)
        menubar.addMenu(edit_menu)

        # Help
        help_menu = QMenu("&Help", self)
        act_about = QAction("ℹ  About", self)
        act_about.triggered.connect(self._open_about)
        help_menu.addAction(act_about)
        menubar.addMenu(help_menu)

        self.setMenuBar(menubar)

    # ── CONFIG ────────────────────────────────────────────────────────────────
    def _load_config(self):
        theme = self._config.get("theme")
        ThemeManager.apply(QApplication.instance(), theme)
        self._update_theme_btn_label()

        direction = self._config.get("direction")
        if direction == "to_json":
            self._dir_to_json.setChecked(True)
        elif direction == "to_uri":
            self._dir_to_uri.setChecked(True)
        else:
            self._dir_auto.setChecked(True)

    def _save_config(self):
        self._config.set("theme", ThemeManager.current)
        bid = self._dir_group.checkedId()
        direction = {0: "auto", 1: "to_json", 2: "to_uri"}.get(bid, "auto")
        self._config.set("direction", direction)
        self._config.save()

    # ── THEME ─────────────────────────────────────────────────────────────────
    def _toggle_theme(self):
        new = "dark" if ThemeManager.current == "light" else "light"
        ThemeManager.apply(QApplication.instance(), new)
        self._update_theme_btn_label()
        self._save_config()

    def _update_theme_btn_label(self):
        if ThemeManager.is_dark():
            self._theme_btn.setText("☀️  Light Mode")
            self._title_lbl.setStyleSheet(
                "color: #00CFFF; font-size: 20px; font-weight: 900; "
                "letter-spacing: 6px; font-family: 'Consolas', monospace;"
            )
        else:
            self._theme_btn.setText("🌙  Dark Mode")
            self._title_lbl.setStyleSheet(
                "color: #0099CC; font-size: 20px; font-weight: 900; "
                "letter-spacing: 6px; font-family: 'Consolas', monospace;"
            )

    # ── CONVERSION ────────────────────────────────────────────────────────────
    def _do_convert(self):
        text = self._input_edit.toPlainText().strip()
        if not text:
            QMessageBox.warning(
                self,
                "No input",
                "Please paste or load a V2Ray JSON config or proxy URI first.",
            )
            return

        bid = self._dir_group.checkedId()
        direction = {0: "auto", 1: "to_json", 2: "to_uri"}.get(bid, "auto")

        self._set_busy(True)
        self._output_edit.clear()
        self._stats_lbl.setText("")

        self._worker = ConvertWorker(text, direction, self)
        self._worker.results_ready.connect(self._on_results)
        self._worker.log_msg.connect(self._log_panel.add)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    def _on_results(self, results: list):
        if not results:
            self._stats_lbl.setText("No convertible content found.")
            self._stats_lbl.setStyleSheet(
                f"color: {ThemeManager.warning_color()}; "
                "font-size: 11px; font-weight: 600;"
            )
            return

        output_lines: List[str] = []
        multiple = len(results) > 1
        ok_count = 0
        err_count = 0

        for hint, result in results:
            if result.startswith("# ERROR:"):
                err_count += 1
            else:
                ok_count += 1
            if multiple:
                output_lines.append(f"# ── {hint}")
            output_lines.append(result)
            if multiple:
                output_lines.append("")  # blank separator between entries

        self._output_edit.setPlainText("\n".join(output_lines).strip())

        msg = f"✔  {ok_count} converted"
        if err_count:
            msg += f"   ·   ✘  {err_count} error(s)"
        color = (
            ThemeManager.accent_color()
            if err_count == 0
            else ThemeManager.warning_color()
        )
        self._stats_lbl.setText(msg)
        self._stats_lbl.setStyleSheet(
            f"color: {color}; font-size: 11px; font-weight: 600;"
        )

    def _on_finished(self, success: bool):
        self._set_busy(False)
        if success:
            self._status_bar.showMessage("Conversion complete.", 4000)
        else:
            self._status_bar.showMessage(
                "Conversion failed — see log for details.", 6000
            )
        self._save_config()

    def _set_busy(self, busy: bool):
        self._convert_btn.setEnabled(not busy)
        self._load_btn.setEnabled(not busy)
        if busy:
            self._convert_btn.setText("⏳  Converting…")
            self._activity.start("Converting")
        else:
            self._convert_btn.setText("⚡  Convert")
            self._activity.stop()

    # ── FILE OPERATIONS ───────────────────────────────────────────────────────
    def _load_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Config or URI File",
            str(Path.home()),
            "All Files (*);;Text Files (*.txt);;JSON Files (*.json)",
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self._input_edit.setPlainText(content)
                self._log_panel.add(f"Loaded: {path}", "INFO")
                self._status_bar.showMessage(f"Loaded: {Path(path).name}", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Load Error", f"Could not read file:\n{e}")

    def _save_output(self):
        text = self._output_edit.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "No output", "There is nothing to save yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Output",
            str(Path.home() / "converted.txt"),
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*)",
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text + "\n")
                self._log_panel.add(f"Output saved to: {path}", "SUCCESS")
                self._status_bar.showMessage(f"Saved: {Path(path).name}", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Save Error", f"Could not save file:\n{e}")

    # ── CLIPBOARD ─────────────────────────────────────────────────────────────
    def _paste_clipboard(self):
        text = QApplication.clipboard().text()
        if text:
            self._input_edit.setPlainText(text)
            self._log_panel.add("Pasted from clipboard.", "INFO")
        else:
            QMessageBox.information(
                self, "Clipboard Empty", "The clipboard contains no text."
            )

    def _copy_output(self):
        text = self._output_edit.toPlainText().strip()
        if text:
            QApplication.clipboard().setText(text)
            self._status_bar.showMessage("Output copied to clipboard.", 3000)
            self._log_panel.add("Output copied to clipboard.", "SUCCESS")
        else:
            QMessageBox.information(
                self, "No Output", "There is no output to copy yet."
            )

    # ── CHAINED CONVERSION ────────────────────────────────────────────────────
    def _use_output_as_input(self):
        text = self._output_edit.toPlainText().strip()
        if text:
            self._input_edit.setPlainText(text)
            self._output_edit.clear()
            self._stats_lbl.setText("")
            self._log_panel.add("Output moved to input for chained conversion.", "INFO")
        else:
            QMessageBox.information(
                self, "No Output", "There is no output to use as input."
            )

    # ── SAMPLE ────────────────────────────────────────────────────────────────
    def _insert_sample(self):
        sample = (
            "vless://12345678-abcd-abcd-abcd-123456789abc@example.com:443"
            "?encryption=none&security=tls&type=ws"
            "&host=example.com&path=%2Fws&sni=example.com&fp=chrome"
            "#My-VLESS-Node"
        )
        self._input_edit.setPlainText(sample)
        self._log_panel.add("Sample VLESS URI inserted.", "INFO")

    # ── CLEAR HELPERS ─────────────────────────────────────────────────────────
    def _input_edit_clear(self):
        self._input_edit.clear()

    def _clear_output(self):
        self._output_edit.clear()
        self._stats_lbl.setText("")

    def _clear_all(self):
        self._input_edit.clear()
        self._output_edit.clear()
        self._stats_lbl.setText("")
        self._log_panel.add("All fields cleared.", "INFO")

    # ── ABOUT ─────────────────────────────────────────────────────────────────
    def _open_about(self):
        AboutDialog(self).exec()

    # ── DRAG AND DROP ─────────────────────────────────────────────────────────
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        urls = event.mimeData().urls()
        if urls:
            local = Path(urls[0].toLocalFile())
            if local.exists() and local.is_file():
                try:
                    with open(local, "r", encoding="utf-8") as f:
                        content = f.read()
                    self._input_edit.setPlainText(content)
                    self._log_panel.add(f"Dropped file loaded: {local.name}", "INFO")
                    self._status_bar.showMessage(f"Loaded: {local.name}", 3000)
                    event.acceptProposedAction()
                except Exception as e:
                    QMessageBox.critical(
                        self, "Load Error", f"Could not read dropped file:\n{e}"
                    )

    # ── CLOSE ─────────────────────────────────────────────────────────────────
    def closeEvent(self, event):
        self._save_config()
        event.accept()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(APP_COMPANY)
    try:
        app.setWindowIcon(QIcon("icon.ico"))
    except Exception:
        pass
    ThemeManager.apply(app, "light")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
