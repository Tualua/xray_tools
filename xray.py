from enum import Enum
import json
import jsonpickle


class XrayLogLevel(Enum):
    Info = "info"
    Warning = "warning"
    Debug = "debug"


class XrayFlow(Enum):
    XTLSRPRXDIRECT = "xtls-rprx-direct"


class XrayProtocol(Enum):
    VLESS = "vless"
    VMESS = "vmess"
    FREEDOM = "freedom"


class XrayNetwork(Enum):
    TCP = "tcp"
    WS = "ws"


class XraySecurity(Enum):
    TLS = "tls"
    XTLS = "xtls"
    NONE = "none"


class XrayAlpn(Enum):
    HTTP11 = "http/1.1"
    H2 = "h2"


class XrayFallback:
    dest: int

    def __init__(self, dest: int, path: str = "", xver: int = 0):
        self.dest = dest

        if path:
            self.path = path

        if xver > 0:
            self.xver = xver


class XrayCertificate:
    certificateFile: str
    keyFile: str


class XrayProtocolSettings:
    pass


class XrayXtlsSettings(XrayProtocolSettings):
    alpn: list[XrayAlpn]
    certificates: list[XrayCertificate]


class XrayWsSettings(XrayProtocolSettings):
    acceptProxyProtocol: bool
    path: str


class XrayClient:
    id: str
    email: str
    level: int

    def __init__(
            self, id: str, email: str,  flow: XrayFlow,
            level=1, aead=False):

        self.id = id
        self.name = email
        self.level = level
        if aead:
            self.alterid = 64

        if flow is not None:
            self.flow = flow


class XrayInboundSettings:
    clients: list[XrayClient]
    decryption: str
    fallbacks: list[XrayFallback]

    def __init__(self, decryption: str):
        self.decryption = decryption
        self.clients = []
        self.fallbacks = []

    def add_client(
            self, id: str, email: str, flow: XrayFlow = None,
            level: int = 1):

        self.clients.append(
            XrayClient(id, email, flow, level)
        )

    def add_fallback(self, dest: int, path: str = "", xver: int = 0):
        self.fallbacks.append(XrayFallback(dest, path, xver))


class XrayInboundStreamSettings:
    network: XrayNetwork
    security: XraySecurity

    def __init__(
            self, network: XrayNetwork, security: XraySecurity,
            settings: XrayProtocolSettings):
        self.network = network
        self.security = security

        if security == XraySecurity.XTLS:
            self.xtlsSettings = settings

        if network == XrayNetwork.WS:
            self.wsSettings = settings


class XrayLog:
    loglevel: XrayLogLevel

    def __init__(
            self, loglevel: XrayLogLevel, path_errorlog: str = "",
            path_accesslog: str = ""):

        self.loglevel = loglevel
        if path_errorlog:
            self.error = path_errorlog

        if path_accesslog:
            self.access = path_accesslog


class XrayInbound:
    port: int
    protocol: XrayProtocol
    listen: str
    settings: XrayInboundSettings
    streamSettings: XrayInboundStreamSettings

    def __init__(
            self, port: int, protocol: XrayProtocol,
            settings: XrayInboundSettings,
            stream_settings: XrayInboundStreamSettings, listen: str = ""):

        self.port = port
        self.protocol = protocol
        if listen:
            self.listen = listen
        self.settings = settings
        self.streamSettings = stream_settings

    def set_stream_network(self, network: XrayNetwork):
        self.streamSettings.network = network

    def set_stream_security(self, security: XraySecurity):
        self.streamSettings.security = security

        if security == XraySecurity.XTLS:
            



class XrayOutbound:
    protocol: XrayProtocol

    def __init__(self, protocol: XrayProtocol):
        self.protocol = protocol


class XrayConfig:
    log: XrayLog
    inbounds: list[XrayInbound]
    outbounds: list[XrayOutbound]

    def __init__(
            self, log: XrayLog):

        self.log = log
        self.inbounds = []
        self.outbounds = []

    def add_inbound(self, inbound: XrayInbound):
        self.inbounds.append(inbound)

    def add_outbound(self, protocol: XrayProtocol):
        self.outbounds.append(XrayOutbound(XrayProtocol.FREEDOM))

    def toJSON(self):
        return json.dumps(
            self, default=lambda o: o.__dict__,
            sort_keys=False, indent=4)


class HandlerXrayProtocol(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XrayProtocol, data):
        return obj.value


class HandlerXrayFlow(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XrayFlow, data):
        return obj.value


jsonpickle.handlers.registry.register(XrayProtocol, HandlerXrayProtocol)
jsonpickle.handlers.registry.register(XrayFlow, HandlerXrayFlow)
