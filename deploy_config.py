from base64 import decodebytes
import paramiko
import yaml
import argparse
import sys
import os


def get_servers(file):
    servers_file = open(file)
    servers = yaml.load(servers_file.read(), Loader=yaml.SafeLoader)
    servers_file.close()
    enabled_servers = {}
    for server in servers["all"]["hosts"]:
        if servers["all"]["hosts"][server]["enabled"]:
            enabled_servers[server] = servers["all"]["hosts"][server]
    return enabled_servers


def main(args):
    deploy_failed = False
    servers = get_servers("servers_ansible.yaml")
    ssh_client = paramiko.SSHClient()
    pkey = paramiko.agent.Agent().get_keys()[0]
    for server in servers:
        if servers[server]["ansible_port"] != 22:
            hostname = "[{}]:{}".format(server, servers[server]["ansible_port"])
        else:
            hostname = server
        hostkey = paramiko.ECDSAKey(
            data=decodebytes(servers[server]["hostkey"].encode('ascii')))
        ssh_client.get_host_keys().add(
            hostname=hostname,
            keytype="ssh-rsa",
            key=hostkey
        )
        print("Connecting to ", hostname)
        try:
            ssh_client.connect(
                hostname=server,
                port=servers[server]["ansible_port"],
                username=args.user,
                pkey=pkey)
        except Exception as e:
            deploy_failed = True
            print(e)
        else:
            print("Connected: ", hostname)
            sftp_client = ssh_client.open_sftp()
            local_config = "{}.json".format(server)
            print("Sending config: ", hostname)
            sftp_client.put(local_config, servers[server]["conf_path"])
            sftp_client.close()
            print("Restarting xray: ", hostname)
            _, stdout, stderr = ssh_client.exec_command(
                servers[server]["reload_cmd"])
            if stdout.read():
                print(stdout.read().decode("utf-8"))
            if stderr.read():
                print("ERROR: ", stderr.read().decode("utf-8"))
                deploy_failed = True
        finally:
            ssh_client.close()
    if deploy_failed:
        sys.exit(1)
    else:
        sys.exit(os.EX_OK)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray Config Uploader"
    )
    parser.add_argument(
        "--user", type=str, action="store", help="User list in JSON")
    args = parser.parse_args()
    main(args)
