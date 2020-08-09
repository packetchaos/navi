import click
from .api_wrapper import request_delete, request_data
from .user import get_user_id


def create_group(group_name):
    payload = {'name': group_name}
    # Using the Delete request because of an API Return issue.
    data = request_delete("POST", "/groups", payload=payload)

    return data


def add_users(user_id, group_id):
    url = "/groups/{}/users/{}".format(group_id, user_id)
    # Using the Delete request because of an API Return issue.
    request_delete("POST", url)


def remove_user(user_id, group_id):
    url = "/groups/{}/users/{}".format(group_id, user_id)
    # Using the Delete request because of an API Return issue.
    request_delete("DELETE", url)


def get_group_id(group_name):
    data = request_data("GET", "/groups")
    group_id = 0
    for group in data["groups"]:

        if group_name == group["name"]:
            group_id = group["id"]
    return group_id


@click.command(help="Create a group or Add/remove a user from a group")
@click.option("-new", is_flag=True, help="Create a new Group. Required: --name")
@click.option("-add", is_flag=True, help="Add a user to a group. Required: --user and --name")
@click.option("--name", default='', help="The Name of the group")
@click.option("--user", default='', help="The User Name to be added or removed")
@click.option("-remove", is_flag=True, help="Remove a user from a group. Requires --name and user")
def usergroup(new, add, name, user, remove):

    if new:
        if name == '':
            print("\nYou must supply a Name for the group")
            exit()
        # Check to see if the group already exists
        group_id = get_group_id(name)
        if group_id == 0:
            create_group(name)
        else:
            print("Your Group already exists. Hers the group id {}".format(group_id))

    if add:
        if user == '' or name == '':
            print("\nYou must supply a username and group name")
            exit()

        user_id = get_user_id(user)
        group_id = get_group_id(name)
        add_users(user_id, group_id)

    if remove:
        if user == '' or name == '':
            print("\nYou must supply a username and group name")
            exit()

        user_id = get_user_id(user)
        group_id = get_group_id(name)
        remove_user(user_id, group_id)
