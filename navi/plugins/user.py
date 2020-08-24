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


@click.group(help="Enable, Disable or add users")
def user():
    pass


@user.command(help="Add a User to Tenable.io - User will be enabled if already exists")
@click.option("--username", "--u", default='', required=True, help="Username")
@click.option("--password", "--p", default='', required=True, help="Users password")
@click.option("--permission", "--m", default='', required=True, help="Users Permission: (16,24,32,40,64)")
@click.option("--name", "--n", default='', required=True, help="Users Name")
@click.option("--email", "--e", default='', required=True, help="Users email")
def add(username, password, permission, name, email):

    if len(password) < 11:
        click.echo("Password must be 12 chars, 1 Upper, 1 lower and 1 Special Char")
        exit()

    # Check to see has already been created
    user_id = get_user_id(username)

    if user_id == 0:
        # if the user doesn't exist. Create it.
        create_user(username, password, permission, name, email)
    else:
        # If the user is trying to create the user, and it already exists, Try to enable it instead
        enable_disable_user(user_id, "enable")


@user.command(help="Enable a user by ID")
@click.argument('uid')
def enable(uid):
    enable_disable_user(uid, "enable")


@user.command(help="Disable a user by ID")
@click.argument('uid')
def disable(uid):
    enable_disable_user(uid, "disable")
