import json
import pyqrcode
import base64
import os
import yaml
import argparse

CL_TYPES = ['v2rayng', 'shadowrocket']


def get_servers(file):
    servers_file = open(file)
    servers = yaml.load(servers_file.read(), Loader=yaml.SafeLoader)
    servers_file.close()
    return servers["servers"]


def get_users(file):
    users_file = open(file)
    users = json.loads(users_file.read())
    users_file.close
    return users["clients"]


def get_shadowrocket_url(proto, id, server, port):
    if proto == "vless":
        b64_part = base64.b64encode(
            f"auto:{id}@{server}:{port}".encode('ascii')
        ).decode('ascii').replace('=', '')
        return f"vless://{b64_part}?obfs=none&tls=1&xtls=1"


def get_vrayng_url(proto, id, server, port):
    comment = server.split(".")[0].upper()
    if proto == "vless":
        b64_part = (
            f"{id}@{server}:{port}?security=xtls&encryption=none&"
            "headerType=none&type=tcp&"
            f"flow=xtls-rprx-direct&sni={server}#{comment}")
        return f"vless://{b64_part}"


def get_xray_url(cl_type, proto, id, server, port):
    if cl_type == "v2rayng":
        return get_vrayng_url(proto, id, server, port)
    elif cl_type == "shadowrocket":
        return get_shadowrocket_url(proto, id, server, port)
    else:
        return None


def get_vmess_qrcode(url):
    return pyqrcode.create(url, error='H')


def main(args):

    users = get_users("users.json")
    servers = get_servers("servers.yaml")

    if not os.path.exists(args.savepath):
        os.makedirs(args.savepath)

    for user in users:
        print("User: {}".format(user["email"]))
        user_dir = os.path.join(args.savepath, user["email"])
        urls = {}
        if not os.path.exists(user_dir):
            os.makedirs(user_dir)
        for cl_type in CL_TYPES:
            urls[cl_type] = []
            for server in servers:
                save_dir = os.path.join(user_dir, cl_type)
                if not os.path.exists(save_dir):
                    os.makedirs(save_dir)
                url = get_xray_url(
                    cl_type, "vless", user["id"], server["name"], 443)
                urls[cl_type].append(f"{url}\n")
                try:
                    get_vmess_qrcode(url).png(
                        "{}//{}-{}.png".format(
                            save_dir, user["email"], server["name"]),
                        scale=5
                    )
                except Exception as e:
                    print('Unable to save QR-code!')
                    print(e)
            urls_file = open(os.path.join(user_dir, f"{cl_type}.txt"), "w")
            urls_file.writelines(urls[cl_type])
            urls_file.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray QR Code generator"
    )
    parser.add_argument(
        "--savepath", type=str, action="store", help="Path to save QR-codes")
    args = parser.parse_args()
    main(args)
