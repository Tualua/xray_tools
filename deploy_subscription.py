import json
import yaml
import base64
import pyqrcode
from urllib.parse import quote
import paramiko
import os
import sys


def get_servers(file):
    servers_file = open(file)
    servers = yaml.load(servers_file.read(), Loader=yaml.SafeLoader)
    servers_file.close()
    enabled_servers = []
    for server in servers["servers"]:
        if server["enabled"]:
            enabled_servers.append(server)
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


def get_shadowrocket_url(proto, id, server, port, desc):
    remarks = quote(desc, safe='/:?=&')
    if proto == "vless":
        b64_part = base64.b64encode(
            f"auto:{id}@{server}:{port}".encode('ascii')
        ).decode('ascii').replace('=', '')
        return f"vless://{b64_part}?obfs=none&tls=1&xtls=1&sni={server}&remarks={remarks}"


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


deploy_failed = False
subs_server = get_subs_server("sub.yaml")
servers = get_servers("servers.yaml")
users = get_users("users.json")
ssh_client = paramiko.SSHClient()
pkey = paramiko.agent.Agent().get_keys()[0]
if subs_server["port"] != 22:
    hostname = "[{}]:{}".format(subs_server["hostname"], subs_server["port"])
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
    for usr in users:
        sr = ""
        subs_usr_dir = os.path.join(subs_server["path"], usr["id"])
        try:
            sftp_client.stat(subs_usr_dir)
        except IOError:
            print(f"Create {subs_usr_dir}")
            sftp_client.mkdir(subs_usr_dir, 436)
        subs_path = os.path.join(subs_server["path"], usr["id"], "rocket.txt")
        print(f"Writing {subs_path}")
        sftp_file = sftp_client.file(
            subs_path,
            "w",
            -1
        )
        for server in servers:
            sr_url = get_shadowrocket_url(
                "vless", usr["id"], server["name"], 443, server["description"])
            sr = sr+"\n"+sr_url
        sr_b64 = base64.b64encode(
            sr.encode('ascii')).decode('ascii').replace('=', '')
        sftp_file.write(sr_b64)
        sftp_file.close()

        sub_srv = base64.b64encode(
            "https://{}/{}/rocket.txt".format(
                subs_server["hostname"],
                usr["id"]).encode('ascii')).decode('ascii').replace('=', '')
        sub_b64 = f"sub://{sub_srv}?udp=1#CET"
        qr = pyqrcode.create(sub_b64, error='H')
        qr.png(
                            "{}/SR-{}.png".format(
                                "/tmp", usr["email"]),
                            scale=5
                        )
    sftp_client.close()
finally:
    ssh_client.close()

if deploy_failed:
    sys.exit(1)
else:
    sys.exit(os.EX_OK)
