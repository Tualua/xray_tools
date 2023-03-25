from .enums import (
    XrayAlpn,
    TLSVersion
)
from .cert import XrayCertificate


class XrayProtocolSettings:
    pass


class XrayXtlsSettings(XrayProtocolSettings):
    alpn: list[XrayAlpn]
    certificates: list[XrayCertificate]

    def __init__(
            self, alpn: list[XrayAlpn], certificates: list[XrayCertificate]):

        self.alpn = alpn
        self.certificates = certificates

    def add_cert(self, cert_path: str, key_path: str):
        cert = XrayCertificate(cert_path, key_path)
        self.certificates.append(cert)


class XrayTlsSettings(XrayProtocolSettings):
    alpn: list[XrayAlpn]
    certificates: list[XrayCertificate]

    def __init__(
            self, alpn: list[XrayAlpn], certificates: list[XrayCertificate]):

        self.alpn = alpn
        self.certificates = certificates
        self.minVersion = TLSVersion.TLS12
        self.cipherSuites = \
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:" + \
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:" + \
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:" + \
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:" + \
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:" + \
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

    def add_cert(self, cert_path: str, key_path: str):
        cert = XrayCertificate(cert_path, key_path)
        self.certificates.append(cert)


class XrayWsSettings(XrayProtocolSettings):
    acceptProxyProtocol: bool
    path: str

    def __init__(self, accept_proxy_protocol: bool, path: str):
        self.acceptProxyProtocol = accept_proxy_protocol
        self.path = path


class XrayTcpSettings(XrayProtocolSettings):
    acceptProxyProtocol: bool

    def __init__(self, accept_proxy_protocol: bool):
        self.acceptProxyProtocol = accept_proxy_protocol


class XrayHttpSettings(XrayProtocolSettings):
    path: str

    def __init__(self, path: str):
        self.path = path
