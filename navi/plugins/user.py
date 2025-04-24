import click
from .api_wrapper import request_data, request_no_response


def create_user(username, password, permission, name, email):

    payload = {"username": "{}".format(str(username)), "password": str(password), "permissions": permission, "name": name, "email": "{}".format(str(email))}

    data = request_no_response("POST", "/users", payload=payload)

    return data


def enable_disable_user(user_id, answer):

    if answer == "enable":
        payload = {"enabled": True}
    else:
        payload = {"enabled": False}

    request_no_response("PUT", "/users/" + str(user_id) + "/enabled", payload=payload)


def change_auth_settings(user_id, payload):
    request_no_response("PUT", "/users/{}/authorizations".format(user_id), payload=payload)


def get_user_id(username):
    data = request_data("GET", "/users")
    user_id = 0
    user_uuid = 0
    for u in data["users"]:
        if username.lower() == u["username"]:
            user_id = u["id"]
            user_uuid = u['uuid']
    return user_id, user_uuid


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
    user_id, user_uuid = get_user_id(username)

    if user_id == 0:
        # if the user doesn't exist. Create it.
        create_user(username, password, permission, name, email)
    else:
        # If the user is trying to create the user, and it already exists, Try to enable it instead
        enable_disable_user(user_id, "enable")


@user.command(help="Enable Auth settings or an Account")
@click.argument('uid')
@click.option('-account', is_flag=True, help="Enable User Account")
@click.option('-api', is_flag=True, help="Enable API Access")
@click.option('-pwd', is_flag=True, help="Enable Password Access")
@click.option('-saml', is_flag=True, help="Enable SAML Access")
def enable(uid, api, pwd, saml, account):
    payload = {"api_permitted": False, "password_permitted": False, "saml_permitted": False}
    if api:
        payload["api_permitted"] = True

    if pwd:
        payload["password_permitted"] = True

    if saml:
        payload["saml_permitted"] = True

    if api or pwd or saml:
        change_auth_settings(uid, payload)

    if account:
        enable_disable_user(uid, "enable")

    if not account and not api and not pwd and not saml:
        click.echo("\nYou need to specify an option\n\nIf you want to disable an account use the '-account' option\n")


@user.command(help="Disable a user by ID or auth settings")
@click.argument('uid')
@click.option('-account', is_flag=True, help="Enable User Account")
@click.option('-api', is_flag=True, help="Enable API Access")
@click.option('-pwd', is_flag=True, help="Enable Password Access")
@click.option('-saml', is_flag=True, help="Enable SAML Access")
def disable(uid, account, api, pwd, saml):

    payload = {"api_permitted": True, "password_permitted": True, "saml_permitted": True}

    if api:
        payload["api_permitted"] = False

    if pwd:
        payload["password_permitted"] = False

    if saml:
        payload["saml_permitted"] = False

    if api or pwd or saml:
        change_auth_settings(uid, payload)

    if account:
        enable_disable_user(uid, "disable")

    if not account and not api and not pwd and not saml:
        click.echo("\nYou need to specify an option\n\nIf you want to disable an account use the '-account' option\n")



@click.group(help="Create a user group or Add/remove a user from a user group")
def usergroup():
    pass


@usergroup.command(help="Create a new user group")
@click.option("--name", default='', required=True, help="The Name of the user group")
def create(name):
    # Check to see if the group already exists
    group_id, group_uuid = get_group_id(name)
    if group_id == 0:
        create_group(name)
    else:
        print("Your Group already exists. Here is the group id {}".format(group_id))


@usergroup.command(help="Add a User to a user group")
@click.option("--name", default='', required=True, help="The Name of the user group")
@click.option("--user", default='', required=True, help="The User Name to be added")
def add(name, user):
    user_id, user_uuid = get_user_id(user)
    group_id, group_uuid = get_group_id(name)
    add_users(user_id, group_id)


@usergroup.command(help="Remove a User from a user group")
@click.option("--name", default='', required=True, help="The Name of the group")
@click.option("--user", default='', required=True, help="The User Name to be removed")
def remove(name, user):
    user_id, user_uuid = get_user_id(user)
    group_id, group_uuid = get_group_id(name)
    remove_user(user_id, group_id)
