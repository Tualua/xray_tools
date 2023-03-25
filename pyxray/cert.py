class XrayCertificate:
    certificateFile: str
    keyFile: str

    def __init__(self, cert_path: str, key_path: str):
        self.certificateFile = cert_path
        self.keyFile = key_path
