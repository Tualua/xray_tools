import json
import yaml


def get_users(file):
    users_file = open(file)
    users = json.loads(users_file.read())
    users_file.close
    return users


def users_to_yaml(users, file):
    users_file = open(file, "w")
    yaml.dump(users, users_file)


users = get_users("users.json")
users_to_yaml(users, "users.yaml")
