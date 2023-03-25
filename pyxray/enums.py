from enum import Enum
import jsonpickle


class ClientType(Enum):
    SR = "ShadowRocket"
    V2RN = "v2rayN"


class TLSVersion(Enum):
    TLS12 = "1.2"
    TLS13 = "1.3"


class SniffingProtocols(Enum):
    HTTP = "http"
    TLS = "tls"


class XrayLogLevel(Enum):
    Info = "info"
    Warning = "warning"
    Debug = "debug"


class XrayFlow(Enum):
    XTLSRPRXDIRECT = "xtls-rprx-direct"
    XTLSRPRXVISION = "xtls-rprx-vision"


class XrayProtocol(Enum):
    VLESS = "vless"
    VMESS = "vmess"
    TROJAN = "trojan"
    FREEDOM = "freedom"


class XrayNetwork(Enum):
    TCP = "tcp"
    WS = "ws"
    H2 = "h2"


class XraySecurity(Enum):
    TLS = "tls"
    XTLS = "xtls"
    NONE = "none"


class XrayAlpn(Enum):
    HTTP11 = "http/1.1"
    H2 = "h2"
    NONE = ""


class HandlerXrayLogLevel(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XrayLogLevel, data):
        return obj.value


class HandlerTlsVerion(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: TLSVersion, data):
        return obj.value


class HandlerXrayProtocol(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XrayProtocol, data):
        return obj.value


class HandlerXrayFlow(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XrayFlow, data):
        return obj.value


class HandlerXrayNetwork(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XrayNetwork, data):
        return obj.value


class HandlerXraySecurity(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XraySecurity, data):
        return obj.value


class HandlerXrayAlpn(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: XrayAlpn, data):
        return obj.value


class HandlerSniffingProtocols(jsonpickle.handlers.BaseHandler):
    def flatten(self, obj: SniffingProtocols, data):
        return obj.value


jsonpickle.handlers.registry.register(
    XrayProtocol, HandlerXrayProtocol)
jsonpickle.handlers.registry.register(
    TLSVersion, HandlerTlsVerion)
jsonpickle.handlers.registry.register(
    XrayFlow, HandlerXrayFlow)
jsonpickle.handlers.registry.register(
    XrayNetwork, HandlerXrayNetwork)
jsonpickle.handlers.registry.register(
    XraySecurity, HandlerXraySecurity)
jsonpickle.handlers.registry.register(
    XrayAlpn, HandlerXrayAlpn)
jsonpickle.handlers.registry.register(
    XrayLogLevel, HandlerXrayLogLevel)
jsonpickle.handlers.registry.register(
    SniffingProtocols, HandlerSniffingProtocols)
