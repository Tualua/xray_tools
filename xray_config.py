import argparse
import xray as X
import jsonpickle
import json


def get_users(file):
    users_file = open(file)
    users = json.loads(users_file.read())
    users_file.close
    return users


def main(args):
    users = get_users(args.users)

    config = X.XrayConfig(
        log=X.XrayLog(
            loglevel=X.XrayLogLevel.Warning,
            path_accesslog="/var/log/xray/acccess.log",
            path_errorlog="/var/log/xray/error.log"
        )
    )

    config.add_inbound(
        port=443,
        protocol=X.XrayProtocol.VLESS,
        network=X.XrayNetwork.TCP,
        security=X.XraySecurity.XTLS,
        settings=X.XrayXtlsSettings(
            alpn=[X.XrayAlpn.HTTP11],
            certificates=[X.XrayCertificate(
                f"/etc/letsencrypt/live/{args.fqdn}/fullchain.pem",
                f"/etc/letsencrypt/live/{args.fqdn}/privkey.pem"
            )]
        ),
        fallbacks=[
            X.XrayFallback(dest=80),
            X.XrayFallback(dest=1234, path="/ray", xver=1)
        ]
    )

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

    config.add_outbound(X.XrayProtocol.FREEDOM)

    for user in users["clients"]:
        config.add_client(user["id"], user["email"])

    out = open(f"{args.fqdn}.json", "w")
    out.write(jsonpickle.encode(config, unpicklable=False, indent=4))
    out.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray Config Generator"
    )
    parser.add_argument(
        "--fqdn", type=str, action="store", help="FQDN of Xray server")
    parser.add_argument(
        "--users", type=str, action="store", help="User list in JSON")
    args = parser.parse_args()
    main(args)
