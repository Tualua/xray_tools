import argparse
import pyxray.config as X
import pyxray.proto as proto
import pyxray.enums as enums
import pyxray.cert as cert
import jsonpickle
import json
import yaml
from datetime import datetime as DT
from dateutil.relativedelta import relativedelta


def get_users(file):
    users_file = open(file)
    users = json.loads(users_file.read())
    users_file.close

    for user in users["clients"]:
        if "valid_till" in user.keys():
            valid = user["valid_till"]
            valid_date = DT.strptime(valid, "%Y%m") + relativedelta(months=1)
            if DT.now() > valid_date:
                users["clients"].remove(user)
                print("User {} expired".format(user["email"]))
    return users


def get_servers(file):
    servers_file = open(file)
    servers = yaml.load(servers_file.read(), Loader=yaml.SafeLoader)
    servers_file.close()
    return servers["all"]["hosts"]


def main(args):
    users = get_users(args.users)
    servers = get_servers("servers_ansible.yaml")
    for server in servers:
        config = X.XrayConfig(
                logging=True,
                log_access="/var/log/xray/access.log",
                log_error="/var/log/xray/error.log"
        )
        # Main TCP-XTLS
        config.add_inbound(
            tag="Vless-TCP-XTLS",
            port=servers[server]["main_port"],
            protocol=X.XrayProtocol.VLESS,
            network=X.XrayNetwork.TCP,
            security=X.XraySecurity.TLS,
            settings=proto.XrayTlsSettings(
                alpn=[enums.XrayAlpn.H2, enums.XrayAlpn.HTTP11],
                certificates=[cert.XrayCertificate(
                    "/etc/letsencrypt/live/{}/fullchain.pem".format(
                        server),
                    "/etc/letsencrypt/live/{}/privkey.pem".format(
                        server)
                )]
            ),
            fallbacks=[
                X.XrayFallback(
                    name=f"trh2-{server}",
                    alpn=enums.XrayAlpn.H2, dest="@trojan-h2"),
                X.XrayFallback(
                    name=f"vlh2-{server}",
                    alpn=enums.XrayAlpn.H2, dest="@vless-h2"),
                X.XrayFallback(path="/rayless", dest="@vless-ws", xver=2),
                X.XrayFallback(path="/ray", dest="@vmess-ws", xver=2),
                X.XrayFallback(
                    alpn=enums.XrayAlpn.H2, dest="@trojan-tcp", xver=2),
                X.XrayFallback(dest="/dev/shm/h1.sock", xver=2),
            ]
        )
        # Vmess Websocket Fallback
        config.add_inbound(
            protocol=X.XrayProtocol.VMESS,
            network=X.XrayNetwork.WS,
            security=X.XraySecurity.NONE,
            settings=proto.XrayWsSettings(
                accept_proxy_protocol=True,
                path="/ray"
            ),
            listen="@vmess-ws"
        )
        # VLESS Websocket Fallback
        config.add_inbound(
            listen="@vless-ws",
            protocol=X.XrayProtocol.VLESS,
            network=X.XrayNetwork.WS,
            security=X.XraySecurity.NONE,
            settings=proto.XrayWsSettings(
                accept_proxy_protocol=True,
                path="/rayless"
            ),
        )
        # VLESS HTTP/2 Fallback
        config.add_inbound(
            listen="@vless-h2",
            protocol=X.XrayProtocol.VLESS,
            network=X.XrayNetwork.H2,
            security=X.XraySecurity.NONE,
            settings=proto.XrayHttpSettings(
                path="/vlh2"
            ),
        )
        # Trojan HTTP/2 Fallback
        config.add_inbound(
            listen="@trojan-h2",
            protocol=X.XrayProtocol.TROJAN,
            network=X.XrayNetwork.H2,
            security=X.XraySecurity.NONE,
            settings=proto.XrayHttpSettings(path="/trjh2"),
        )
        # Trojan TCP Fallback
        config.add_inbound(
            listen="@trojan-tcp",
            protocol=X.XrayProtocol.TROJAN,
            network=X.XrayNetwork.TCP,
            security=X.XraySecurity.NONE,
            settings=proto.XrayTcpSettings(accept_proxy_protocol=True),
            fallbacks=[
                X.XrayFallback(dest="/dev/shm/h2c.sock", xver=2),
            ]
        )
        config.add_outbound(X.XrayProtocol.FREEDOM)

        for user in users["clients"]:
            if "valid_till" in user.keys():
                config.add_client(
                    user["id"], user["email"], user["valid_till"])
            else:
                config.add_client(user["id"], user["email"])

        out = open("{}.json".format(server), "w", newline='\n')
        out.write(jsonpickle.encode(
            config, unpicklable=False, indent=4))
        out.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray Config Generator"
    )
    parser.add_argument(
        "--users", type=str, action="store", help="User list in JSON")
    args = parser.parse_args()
    main(args)
