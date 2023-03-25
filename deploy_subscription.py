import yaml
import json
import base64
import paramiko
import os
import sys
import pyqrcode
from pyxray import url
from pyxray.enums import (
    ClientType,
    XrayProtocol
)


SR_SUBS_URL1 = "https://{}/{}/rocket.txt"
SR_SUBS_URL2 = "sub://{b64}/?udp=1#CET"
V2RAYN_SUBS_URL = "https://{}/{}/v2rayn.txt#CET"


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

ssh_client = paramiko.SSHClient()
pkey = paramiko.agent.Agent().get_keys()[0]
if subs_server["port"] != 22:
    hostname = "[{}]:{}".format(
        subs_server["deploy_hostname"], subs_server["port"])
else:
    hostname = subs_server["deploy_hostname"]
hostkey = paramiko.ECDSAKey(
    data=base64.decodebytes(subs_server["hostkey"].encode('ascii')))
ssh_client.get_host_keys().add(
    hostname=subs_server["deploy_hostname"],
    keytype="ssh-rsa",
    key=hostkey
)
try:
    ssh_client.connect(
        hostname=subs_server["deploy_hostname"],
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
            client_url = url.XrayClientUrl(user, {server: servers[server]})
            sr_urls.extend(
                client_url.get_url(type=ClientType.SR, proto=XrayProtocol.VLESS))
            v2rayn_urls.extend(
                client_url.get_url(type=ClientType.V2RN, proto=XrayProtocol.VLESS))
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
        
        user_sr_subs_url = SR_SUBS_URL1.format(
            subs_server["hostname"], user["id"])
        user_sr_subs_url_b64 = base64.b64encode(
            user_sr_subs_url.encode('ascii')).decode('ascii')
        qr = pyqrcode.create(
            SR_SUBS_URL2.format(b64=user_sr_subs_url_b64), error='H')
        qr.png(
                "{}/{}-Shadowrocket.png".format(
                    "qrcodes", user["email"]),
                scale=5
        )

        user_v2rayn_subs_url = V2RAYN_SUBS_URL.format(
            subs_server["hostname"], user["id"])
        user_v2rayn_subs_url_b64 = base64.b64encode(
            user_v2rayn_subs_url.encode('ascii')).decode('ascii')
        qr = pyqrcode.create(user_v2rayn_subs_url_b64, error='H')
        qr.png(
                "{}/{}-v2rayNG.png".format(
                    "qrcodes", user["email"]),
                scale=5
        )
        v2rayn_links_file = open(
            "{}/{}-v2rayN.txt".format("qrcodes", user["email"]), "w")
        v2rayn_links_file.write(user_v2rayn_subs_url)
        v2rayn_links_file.close()

    sftp_client.close()
finally:
    ssh_client.close()


if deploy_failed:
    sys.exit(1)
else:
    sys.exit(os.EX_OK)
