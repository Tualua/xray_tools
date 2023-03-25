from .enums import SniffingProtocols


class XraySniffing:
    enabled: bool
    destOverride: list[SniffingProtocols]

    def __init__(
            self, enabled: bool = True, destOverride: list[SniffingProtocols] =
            [SniffingProtocols.HTTP, SniffingProtocols.TLS]):
        self.enabled = enabled
        self.destOverride = destOverride
