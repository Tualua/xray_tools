from .enums import XrayProtocol


class XrayOutbound:
    protocol: XrayProtocol

    def __init__(self, protocol: XrayProtocol):
        self.protocol = protocol
