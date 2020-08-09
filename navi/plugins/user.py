import click
from .api_wrapper import request_data, request_delete


def create_user(username, password, permission, name, email):
    payload = {"username": "{}".format(str(username)), "password": str(password), "permissions": permission, "name": name, "email": "{}".format(str(email))}
    # Using the Delete request because of an API Return issue.
    data = request_delete("POST", "/users", payload=payload)

    return data


def enable_disable_user(user_id, answer):

    if answer == "enable":
        payload = {"enabled": True}
    else:
        payload = {"enabled": False}
    # Using the Delete request because of an API Return issue.
    request_delete("PUT", "/users/" + str(user_id) + "/enabled", payload=payload)


def get_user_id(username):
    data = request_data("GET", "/users")
    user_id = 0
    for u in data["users"]:
        if username == u["username"]:
            user_id = u["id"]
    return user_id


@click.command(help="Add, Disable or Enable a user")
@click.option("-add", is_flag=True, help="Add User. Requires: ")
@click.option("--username", "--u", default='', help="Username. Requires: -add")
@click.option("--password", "--p", default='', help="Users password. Requires: -add")
@click.option("--permission", "--m", default='', help="Users Permission: (16,24,32,40,64) Requires: -add")
@click.option("--name", "--n", default='', help="Users Name. Requires: -add")
@click.option("--email", "--e", default='', help="Users email. Requires: -add")
@click.option("--enable", default='', help="Enable user by User ID")
@click.option("--disable", default='', help="Disable user by User ID")
def user(add, username, password, permission, name, email, enable, disable):
    if add:
        if username == '' or password == '' or permission == '' or name == '':
            print("To add a user it requires\n")
            print("Username, password, permissions(8,16,32,64), name and email")
            exit()

        if len(password) < 11:
            print("Password must be 12 chars, 1 Upper, 1 lower and 1 Special Char")
            exit()

        # Check to see has already been created

        user_id = get_user_id(username)

        if user_id == 0:
            # if the user doesn't exist. Create it.
            create_user(username, password, permission, name, email)
        else:
            # If the user is trying to create the user, and it already exists, Try to enable it instead
            enable_disable_user(user_id, "enable")

    if enable:
        enable_disable_user(enable, "enable")

    if disable:
        enable_disable_user(disable, "disable")
