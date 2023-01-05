#!/usr/bin/python3

import json
from datetime import datetime as DT
from dateutil.relativedelta import relativedelta
import argparse
import dbus


def main(args):
    config = json.loads(open(args.config).read())

    config_changed = False

    for inbound in config["inbounds"]:
        for client in inbound["settings"]["clients"]:
            if "valid_till" in client.keys():
                valid = client["valid_till"]
                valid_date = DT.strptime(
                    valid, "%Y%m") + relativedelta(months=1)
                if DT.now() > valid_date:
                    inbound["settings"]["clients"].remove(client)
                    print("User {} expired".format(client["email"]))
                    config_changed = True

    if config_changed:
        updated_config = open(args.config, "w")
        updated_config.write(json.dumps(config, indent=4))
        updated_config.close()
        sysbus = dbus.SystemBus()
        systemd1 = sysbus.get_object(
            'org.freedesktop.systemd1', '/org/freedesktop/systemd1')
        manager = dbus.Interface(systemd1, 'org.freedesktop.systemd1.Manager')
        _ = manager.RestartUnit(f'{args.service}.service', 'fail')

    else:
        print("No expired users found")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Xray Config Cleaner"
    )
    parser.add_argument(
        "--config", type=str, action="store", help="Path to config file")
    parser.add_argument(
        "--service", type=str, action="store", help="Systemd service name")
    args = parser.parse_args()
    main(args)
