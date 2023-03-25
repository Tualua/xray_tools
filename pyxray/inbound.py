from .enums import (
    XrayProtocol,
    XrayAlpn,
    XrayFlow,
    XrayNetwork,
    XraySecurity
)
from .proto import (
    XrayProtocolSettings,
    XrayXtlsSettings
)
from .sniff import XraySniffing


class XrayFallback:
    name: str
    dest: str
    alpn: XrayAlpn

    def __init__(self, dest: int,  name: str = "", path: str = "",
                 xver: int = 1, alpn: XrayAlpn = XrayAlpn.NONE):
        self.dest = dest
        if name:
            self.name = name

        if path:
            self.path = path

        if xver > 0:
            self.xver = xver

        if alpn != XrayAlpn.NONE:
            self.alpn = alpn


class XrayClient:
    id: str
    password: str
    email: str
    level: int

    def __init__(
            self, id: str, email: str,  flow: XrayFlow,
            valid_till: str = "",
            level=1, aead=False, password=False):

        if password:
            self.password = id
        else:
            self.id = id
        self.email = email
        self.level = level
        if not aead:
            self.alterid = 64

        if flow is not None:
            self.flow = flow

        if valid_till:
            self.valid_till = valid_till


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
            valid_till: str = "",
            level: int = 1, aead: bool = False, password: bool = False):

        if password:
            self.clients.append(
                XrayClient(
                    id=id, email=email,
                    flow=flow, valid_till=valid_till,
                    level=level, aead=aead, password=password)
                )
        else:
            self.clients.append(
                XrayClient(
                    id=id, email=email,
                    flow=flow, valid_till=valid_till,
                    level=level, aead=aead)
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

        if security == XraySecurity.TLS and network == XrayNetwork.TCP:
            self.tlsSettings = settings

        if security == XraySecurity.XTLS:
            self.xtlsSettings = settings

        if network == XrayNetwork.WS:
            self.wsSettings = settings

        if security == XraySecurity.NONE and network == XrayNetwork.TCP:
            self.tcpSettings = settings

        if network == XrayNetwork.H2:
            self.httpSettings = settings


class XrayInbound:
    tag: str
    port: int
    protocol: XrayProtocol
    listen: str
    settings: XrayInboundSettings
    streamSettings: XrayInboundStreamSettings
    sniffing: XraySniffing

    def __init__(
            self, protocol: XrayProtocol,
            settings: XrayInboundSettings,
            stream_settings: XrayInboundStreamSettings, listen: str = "",
            port: int = 0,
            fallbacks: list[XrayFallback] = []):

        if port:
            self.port = port
        self.protocol = protocol
        if listen:
            self.listen = listen
        self.settings = settings
        self.streamSettings = stream_settings
        self.sniffing = XraySniffing()

        if len(fallbacks) > 0:
            self.settings.fallbacks = fallbacks

    def set_stream_network(self, network: XrayNetwork):
        self.streamSettings.network = network

    def set_stream_security(self, security: XraySecurity):
        self.streamSettings.security = security

        if security == XraySecurity.XTLS:
            self.streamSettings.xtlsSettings = XrayXtlsSettings(
                alpn=[XrayAlpn.HTTP11], certificates=[])

    def add_client(self, email: str, id: str, valid_till: str = ""):
        if self.protocol == XrayProtocol.VLESS:
            if self.streamSettings.security == XraySecurity.XTLS:
                self.settings.add_client(
                    id=id,
                    email=email,
                    flow=XrayFlow.XTLSRPRXDIRECT,
                    valid_till=valid_till,
                    aead=True
                )
            elif self.streamSettings.network == XrayNetwork.WS:
                self.settings.add_client(
                    id=id,
                    email=email,
                    valid_till=valid_till,
                    aead=True
                )
            elif self.streamSettings.security == XraySecurity.TLS:
                self.settings.add_client(
                    id=id,
                    email=email,
                    flow=XrayFlow.XTLSRPRXVISION,
                    valid_till=valid_till,
                    aead=True
                )
        elif self.protocol == XrayProtocol.VMESS:
            if self.streamSettings.network == XrayNetwork.WS:
                self.settings.add_client(
                    id=id,
                    email=email,
                    valid_till=valid_till
                )
        elif self.protocol == XrayProtocol.TROJAN:
            if self.streamSettings.security == XraySecurity.XTLS:
                self.settings.add_client(
                    id=id,
                    email=email,
                    flow=XrayFlow.XTLSRPRXDIRECT,
                    valid_till=valid_till,
                    aead=True, password=True
                )
            elif self.streamSettings.security == XraySecurity.NONE:
                self.settings.add_client(
                    id=id,
                    email=email,
                    valid_till=valid_till,
                    aead=True, password=True
                )
