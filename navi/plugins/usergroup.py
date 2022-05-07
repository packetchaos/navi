import click
from .api_wrapper import request_no_response, request_data
from .user import get_user_id


def create_group(group_name):
    payload = {'name': group_name}
    # Using the Delete request because of an API Return issue.
    data = request_no_response("POST", "/groups", payload=payload)

    return data


def add_users(user_id, group_id):
    url = "/groups/{}/users/{}".format(group_id, user_id)
    # Using the Delete request because of an API Return issue.
    request_no_response("POST", url)


def remove_user(user_id, group_id):
    url = "/groups/{}/users/{}".format(group_id, user_id)
    # Using the Delete request because of an API Return issue.
    request_no_response("DELETE", url)


def get_group_id(group_name):
    data = request_data("GET", "/groups")
    group_id = 0
    group_uuid = 0
    for group in data["groups"]:

        if group_name == group["name"]:
            group_id = group["id"]
            group_uuid = group['uuid']
    return group_id, group_uuid


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
