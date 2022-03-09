from base64 import decodebytes
import paramiko
import yaml
import argparse


def get_servers(file):
    servers_file = open(file)
    servers = yaml.load(servers_file.read(), Loader=yaml.SafeLoader)
    servers_file.close()
    return servers["servers"]


def main(args):
    servers = get_servers("servers.yaml")
    ssh_client = paramiko.SSHClient()
    pkey = paramiko.agent.Agent().get_keys()[0]
    for server in servers:
        if server["port"] != 22:
            hostname = "[{}]:{}".format(server["name"], server["port"])
        else:
            hostname = server["name"]
        hostkey = paramiko.ECDSAKey(
            data=decodebytes(server["hostkey"].encode('ascii')))
        ssh_client.get_host_keys().add(
            hostname=hostname,
            keytype="ssh-rsa",
            key=hostkey
        )
        print("Connecting to ", hostname)
        try:
            ssh_client.connect(
                hostname=server["name"],
                port=server["port"],
                username=args.user,
                pkey=pkey)
        except Exception as e:
            print(e)
        else:
            print("Connected: ", hostname)
            sftp_client = ssh_client.open_sftp()
            local_config = "{}.json".format(server["name"])
            print("Sending config: ", hostname)
            sftp_client.put(local_config, server["conf_path"])
            sftp_client.close()
            print("Restarting xray: ", hostname)
            _, stdout, stderr = ssh_client.exec_command(server["reload_cmd"])
            print(stdout.read())
            if stderr:
                print("ERROR: ", stderr)
        finally:
            ssh_client.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray Config Uploader"
    )
    parser.add_argument(
        "--user", type=str, action="store", help="User list in JSON")
    args = parser.parse_args()
    main(args)
