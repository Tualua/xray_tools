from .enums import (
    ClientType,
    XrayProtocol,
    XrayAlpn
)
from urllib.parse import quote
import base64

SR_VLESS_WS_URL1 = "auto:{id}@{server}:{port}"
SR_VLESS_WS_URL2 = "vless://{b64}?remarks={remarks}&path={path}&obfs={obfs}" \
    "&tls=1"


class XrayClientUrl(object):
    proto: str
    id: str
    email: str
    server: str
    main_port: int
    sni: str
    description: str

    def __init__(self, user, server):
        self.id = user["id"]
        self.email = user["email"]
        self.server = list(server.keys())[0]
        self.main_port = server[self.server]["main_port"]
        self.sni = self.server
        self.description = server[self.server]["description"]

    def get_url(self, type: ClientType, proto: XrayProtocol):
        client_alpn = quote(",".join([
            str(XrayAlpn.H2.value),
            str(XrayAlpn.HTTP11.value)]
        ), safe="")
        client_url: str = f"{proto.value}://"
        ws_path = quote("/rayless", safe="")
        remarks = quote(self.description+" VLESS WS", safe="")

        if type == ClientType.V2RN:
            client_url = f"""\
                {client_url}{self.id}@{self.server}:{self.main_port}?\
                encryption=none&security=tls&\
                sni={self.server}&alpn={client_alpn}&\
                type=ws&path={ws_path}\
                #{remarks}
            """
        elif type == ClientType.SR:
            b64_data = base64.b64encode(
                SR_VLESS_WS_URL1.format(
                    id=self.id, server=self.server, port=self.main_port
                ).encode('ascii')
            ).decode('ascii').replace('=', '')
            remarks = quote(self.description+" VLESS WS", safe='')
            client_url = SR_VLESS_WS_URL2.format(
                b64=b64_data, remarks=remarks, path=ws_path,
                obfs="websocket",
            )
        return client_url