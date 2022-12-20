import argparse
import xray as X
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
            log=X.XrayLog(
                loglevel=X.XrayLogLevel.Warning,
                path_accesslog="/var/log/xray/access.log",
                path_errorlog="/var/log/xray/error.log"
            )
        )
        # Main TCP-XTLS
        config.add_inbound(
            port=servers[server]["vmess_port"],
            protocol=X.XrayProtocol.VLESS,
            network=X.XrayNetwork.TCP,
            security=X.XraySecurity.XTLS,
            settings=X.XrayXtlsSettings(
                alpn=[X.XrayAlpn.H2, X.XrayAlpn.HTTP11],
                certificates=[X.XrayCertificate(
                    "/etc/letsencrypt/live/{}/fullchain.pem".format(
                        server),
                    "/etc/letsencrypt/live/{}/privkey.pem".format(
                        server)
                )]
            ),
            fallbacks=[
                X.XrayFallback(dest=80, xver=0),
                X.XrayFallback(dest=1234, path="/ray"),
                X.XrayFallback(dest=2345, path="/rayless")
            ]
        )
        # Vmess Websocket Fallback
        config.add_inbound(
            port=1234,
            protocol=X.XrayProtocol.VMESS,
            network=X.XrayNetwork.WS,
            security=X.XraySecurity.NONE,
            settings=X.XrayWsSettings(
                accept_proxy_protocol=True,
                path="/ray"
            ),
            listen="127.0.0.1"
        )
        # VLESS Websocket Fallback
        config.add_inbound(
            port=2345,
            protocol=X.XrayProtocol.VLESS,
            network=X.XrayNetwork.WS,
            security=X.XraySecurity.NONE,
            settings=X.XrayWsSettings(
                accept_proxy_protocol=True,
                path="/rayless"
            ),
            listen="127.0.0.1"
        )
        # Trojan
        config.add_inbound(
            port=servers[server]["trojan_port"],
            protocol=X.XrayProtocol.TROJAN,
            network=X.XrayNetwork.TCP,
            security=X.XraySecurity.XTLS,
            settings=X.XrayXtlsSettings(
                alpn=[X.XrayAlpn.H2, X.XrayAlpn.HTTP11],
                certificates=[X.XrayCertificate(
                    "/etc/letsencrypt/live/{}/fullchain.pem".format(
                        server),
                    "/etc/letsencrypt/live/{}/privkey.pem".format(
                        server)
                )]
            ),
            fallbacks=[
                X.XrayFallback(dest=80, xver=0),
                X.XrayFallback(dest=1234, path="/ray"),
                X.XrayFallback(dest=2345, path="/rayless")
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
