from .enums import (
    XrayProtocol,
    XraySecurity,
    XrayNetwork
)
from .log import (
    XrayLog,
    XrayLogLevel
)
from .inbound import (
    XrayInbound,
    XrayInboundSettings,
    XrayInboundStreamSettings,
    XrayFallback
)
from . import outbound
from . import proto


class XrayConfig:
    log: XrayLog
    inbounds: list[XrayInbound]
    outbounds: list[outbound.XrayOutbound]

    def __init__(
            self, logging: bool, log_access: str = "", log_error: str = "",
            log_level: XrayLogLevel = XrayLogLevel.Warning):

        if logging:
            self.log = XrayLog(
                loglevel=log_level, path_accesslog=log_access,
                path_errorlog=log_error)
        self.inbounds = []
        self.outbounds = []

    def add_inbound(
            self, protocol: XrayProtocol,
            network: XrayNetwork, security: XraySecurity,
            fallbacks: list[XrayFallback] = [],
            listen: str = "",
            port: int = 0,
            tag: str = "",
            settings: proto.XrayProtocolSettings = proto.XrayProtocolSettings(
            )):

        new_inbound = XrayInbound(
                protocol=protocol,
                settings=XrayInboundSettings(
                    decryption="none"
                ),
                stream_settings=XrayInboundStreamSettings(
                    network=network,
                    security=security,
                    settings=settings
                ),
                fallbacks=fallbacks,
                listen=listen
        )
        if tag:
            new_inbound.tag = tag
        if port:
            new_inbound.port = port
        self.inbounds.append(new_inbound)

    def add_outbound(self, protocol: XrayProtocol):
        self.outbounds.append(outbound.XrayOutbound(XrayProtocol.FREEDOM))

    def add_client(self, id: str, email: str, valid_till: str = ""):
        for inb in self.inbounds:
            inb.add_client(email=email, id=id, valid_till=valid_till)
