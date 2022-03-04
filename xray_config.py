import json
import jsonpickle

import xray


def get_users(file):
    users_file = open(file)
    users = json.loads(users_file.read())
    users_file.close
    return users


users = get_users("users.json")

x_log = xray.XrayLog(
    "warning", "/var/log/xray/error.log",
    "/var/log/xray/access.log")

in1set = xray.XrayInboundSettings("none")

for user in users["clients"]:
    in1set.add_client(user["id"], user["email"], xray.XrayFlow.XTLSRPRXDIRECT)

in1set.add_fallback(80)
in1set.add_fallback(1234, "/websocket", 1)

config = xray.XrayConfig(x_log)
config.add_inbound(
    xray.XrayInbound(443, xray.XrayProtocol.VLESS, in1set, None))
config.add_outbound(xray.XrayProtocol.FREEDOM)

out = open("test.json", "w")

out.write(jsonpickle.encode(config, unpicklable=False, indent=4))
out.close()
