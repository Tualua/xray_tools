from .enums import XrayLogLevel


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
