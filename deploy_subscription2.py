import yaml
import json
import base64
import paramiko
import os
import sys
import pyqrcode
from urllib.parse import quote


SR_TROJAN_URL = "trojan://{id}@{server}:{port}?&tls=1&xtls=1&sni={sni}" \
    "#{remarks}"
SR_VLESS_WS_URL1 = "auto:{id}@{server}:{port}"
SR_VLESS_WS_URL2 = "vless://{b64}?remarks={remarks}&path={path}&obfs={obfs}" \
    "&tls=1"
SR_VLESS_XTLS_URL1 = "none:{id}@{server}:{port}"
SR_VLESS_XTLS_URL2 = "vless://{b64}?remarks={remarks}&obfs=none&tls=1&xtls=1"
SR_VMESS_WS_URL1 = "auto:{id}@{server}:{port}"
SR_VMESS_WS_URL2 = "vmess://{b64}?remarks={remarks}&path={path}&obfs={obfs}" \
    "&peer={peer}&tls=1&alterid=0"


class XrayClientUrl(object):
    proto: str
    id: str
    email: str
    server: str
    vmess_port: int
    trojan_port: int
    sni: str
    description: str

    def __init__(self, user, server):
        self.id = user["id"]
        self.email = user["email"]
        self.server = list(server.keys())[0]
        self.vmess_port = server[self.server]["vmess_port"]
        self.trojan_port = server[self.server]["trojan_port"]
        self.sni = self.server
        self.description = server[self.server]["description"]

    def get_sr_urls(self):
        urls = []
        remarks = quote(self.description+" TROJAN", safe='')
        # TROJAN
        url = SR_TROJAN_URL.format(
            id=self.id, server=self.server, port=self.trojan_port,
            sni=self.sni, remarks=remarks
        )
        urls.append(url)

        # VLESS+WS
        b64_data = base64.b64encode(
            SR_VLESS_WS_URL1.format(
                id=self.id, server=self.server, port=self.vmess_port
            ).encode('ascii')
        ).decode('ascii').replace('=', '')
        remarks = quote(self.description+" VLESS WS", safe='')
        url = SR_VLESS_WS_URL2.format(
            b64=b64_data, remarks=remarks, path="/rayless", obfs="websocket",
        )
        urls.append(url)

        # VLESS+XTLS
        b64_data = base64.b64encode(
            SR_VLESS_XTLS_URL1.format(
                id=self.id, server=self.server, port=self.vmess_port
            ).encode('ascii')
        ).decode('ascii').replace('=', '')
        remarks = quote(self.description+" VLESS WS", safe='')
        url = SR_VLESS_XTLS_URL2.format(
            b64=b64_data, remarks=remarks
        )
        urls.append(url)
        # VMESS+WS
        b64_data = base64.b64encode(
            SR_VMESS_WS_URL1.format(
                id=self.id, server=self.server, port=self.vmess_port
            ).encode('ascii')
        ).decode('ascii').replace('=', '')
        remarks = quote(self.description+" VLESS WS", safe='')
        url = SR_VMESS_WS_URL2.format(
            b64=b64_data, remarks=remarks, path="/ray", obfs="websocket",
            peer=self.server
        )
        urls.append(url)

        return urls

    def get_v2rayn_urls(self):
        urls = []
        # TROJAN
        remarks = (self.description+" TROJAN").replace(" ", "+")
        url_data = "{}@{}:{}?security={}&encryption={}&alpn={}&headerType={}" \
                   "&type={}&flow={}&sni={}#{}".format(
                    self.id, self.server, self.trojan_port, "xtls", "none",
                    "h2,http/1.1", "none", "tcp", "xtls-rprx-direct",
                    self.sni, remarks
                    )
        url = "trojan://{}".format(url_data)
        urls.append(url)
        # VLESS+WS
        remarks = (self.description+" VLESS WS").replace(" ", "+")
        url_data = "{}@{}:{}?path={}&security={}&encryption={}&alpn={}" \
                   "&type={}&sni={}#{}".format(
                    self.id, self.server, self.vmess_port,
                    quote("/rayless", safe=''),
                    "tls", "none", "h2,http/1.1", "ws",
                    self.sni, remarks
                    )
        url = "vless://{}".format(url_data)
        urls.append(url)

        # VLESS+XTLS
        remarks = (self.description+" VLESS XTLS").replace(" ", "+")
        url_data = "{}@{}:{}?security={}&encryption={}&headerType={}&type={}" \
                   "&flow={}&sni={}#{}".format(
                    self.id, self.server, self.vmess_port, "xtls", "none",
                    "none", "tcp", "xtls-rprx-direct", self.sni, remarks
                    )
        url = "vless://{}".format(url_data)
        urls.append(url)

        # VMESS+WS
        remarks = (self.description+" VMESS WS")
        url_data = {
            "add": self.server,
            "aid": "0",
            "alpn": "",
            "host": self.server,
            "id": self.id,
            "net": "ws",
            "path": "/ray",
            "port": self.vmess_port,
            "ps": remarks,
            "scy": "auto",
            "sni": self.server,
            "tls": "tls",
            "type": "",
            "v": "2"
        }
        b64_data = base64.b64encode(
            json.dumps(
                url_data,
                separators=(',', ':')).encode('ascii')).decode('ascii')
        url = "vmess://{}".format(b64_data)
        urls.append(url)
        return urls


def get_servers(file):
    servers_file = open(file)
    servers = yaml.load(servers_file.read(), Loader=yaml.SafeLoader)
    servers_file.close()
    enabled_servers = {}
    for server in servers["all"]["hosts"]:
        if servers["all"]["hosts"][server]["enabled"]:
            enabled_servers[server] = servers["all"]["hosts"][server]
    return enabled_servers


def get_subs_server(file):
    server_file = open(file)
    server = yaml.load(server_file.read(), Loader=yaml.SafeLoader)
    server_file.close()
    return server


def get_users(file):
    users_file = open(file)
    users = json.loads(users_file.read())
    users_file.close
    return users["clients"]


deploy_failed = False
subs_server = get_subs_server("sub.yaml")
servers = get_servers("servers_ansible.yaml")
users = get_users("users.json")

for user in users:
    sr_urls = []
    v2rayn_urls = []

    ssh_client = paramiko.SSHClient()
    pkey = paramiko.agent.Agent().get_keys()[0]
    if subs_server["port"] != 22:
        hostname = "[{}]:{}".format(
            subs_server["hostname"], subs_server["port"])
    else:
        hostname = subs_server["hostname"]
    hostkey = paramiko.ECDSAKey(
        data=base64.decodebytes(subs_server["hostkey"].encode('ascii')))
    ssh_client.get_host_keys().add(
        hostname=subs_server["hostname"],
        keytype="ssh-rsa",
        key=hostkey
    )
    try:
        ssh_client.connect(
            hostname=subs_server["hostname"],
            port=subs_server["port"],
            username="root",
            pkey=pkey)
    except Exception as e:
        deploy_failed = True
        print(e)
    else:
        print("Connected: ", hostname)
        sftp_client = ssh_client.open_sftp()
        for user in users:
            sr_urls = []
            v2rayn_urls = []
            subs_usr_dir = os.path.join(subs_server["path"], user["id"])
            try:
                sftp_client.stat(subs_usr_dir)
            except IOError:
                print(f"Create {subs_usr_dir}")
                sftp_client.mkdir(subs_usr_dir, 493)
            subs_sr_path = os.path.join(
                subs_server["path"], user["id"], "rocket.txt")
            subs_v2rayn_path = os.path.join(
                subs_server["path"], user["id"], "v2rayn.txt")
            for server in servers:
                client_url = XrayClientUrl(user, {server: servers[server]})
                sr_urls.extend(client_url.get_sr_urls())
                v2rayn_urls.extend(client_url.get_v2rayn_urls())
                sr_urls_b64 = base64.b64encode(
                    "\n".join(sr_urls).encode('ascii')).decode('ascii')
                v2rayn_urls_b64 = base64.b64encode(
                    "\n".join(v2rayn_urls).encode('ascii')).decode('ascii')

            print(f"Writing {subs_sr_path}")
            sftp_file = sftp_client.file(
                subs_sr_path,
                "w",
                -1
            )
            sftp_file.write(sr_urls_b64)
            sftp_file.close()

            print(f"Writing {subs_v2rayn_path}")
            sftp_file = sftp_client.file(
                subs_v2rayn_path,
                "w",
                -1
            )
            sftp_file.write(v2rayn_urls_b64)
            sftp_file.close()

            qr = pyqrcode.create(sr_urls_b64, error='H')
            qr.png(
                    "{}/SR-{}.png".format(
                        "qrcodes", user["email"]),
                    scale=5
            )
            qr = pyqrcode.create(v2rayn_urls_b64, error='H')
            qr.png(
                    "{}/V2RAYN-{}.png".format(
                        "qrcodes", user["email"]),
                    scale=5
            )
        sftp_client.close()
    finally:
        ssh_client.close()

if deploy_failed:
    sys.exit(1)
else:
    sys.exit(os.EX_OK)
