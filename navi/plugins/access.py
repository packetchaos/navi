import click
from .database import db_query
from .api_wrapper import request_data, tenb_connection
from .usergroup import get_group_id
from .user import get_user_id
import pprint


tio = tenb_connection()


def create_permission(name, tag_name, uuid, perm_string, perm_type, subject_type):
    payload = {
        "actions": ["{}".format(perm_string)],
        "objects": [
            {
                "name": name,
                "type": perm_type,
                "uuid": str(uuid)
            }
        ],
        "subjects": [{"type": subject_type}],
        "name": "{} : [{}]".format(tag_name, perm_string)
    }
    response = request_data("POST", "/api/v3/access-control/permissions", payload=payload)
    return response


def create_granular_permission(tag_name, uuid, perm_list, perm_type, subject_type, subject_name, subject_uuid):
    payload = {
        "actions": perm_list,
        "objects": [
            {
                "name": tag_name,
                "type": perm_type,
                "uuid": str(uuid)
            }
        ],
        "subjects": [{"name": subject_name, "type": subject_type, "uuid": subject_uuid}],
        "name": "{} : {}".format(tag_name, perm_list)
    }
    response = request_data("POST", "/api/v3/access-control/permissions", payload=payload)
    return response


def grab_can_use_tags():
    data = request_data("GET", "/api/v3/access-control/permissions")

    list_of_tag_uuids = []
    # Filter on just permissions
    for perms in data['permissions']:
        # Need to search for CanView
        if 'CanUse' in str(perms['actions']):

            # Extract all Tag UUIDs
            for tag in perms['objects']:
                try:
                    if tag['type'] == 'Tag':
                        list_of_tag_uuids.append(tag['uuid'])
                except KeyError:
                    pass
    return list_of_tag_uuids


@click.group(help="Change Access Control Permissions")
def access():
    pass


@access.command(help="Change Access Control Permissions using a Tag")
@click.option('--c', default='', required=True, help="Tag Category name to use")
@click.option('--v', default='', required=True, help="Tag Value to use")
@click.option('--user', default='', help="The User you want to assign to the Permission")
@click.option('--usergroup', default='', help="The User Group you want to assign to the Permission")
@click.option('--perm', multiple=True, type=click.Choice(['CanScan', 'CanView', 'CanEdit', 'CanUse'], case_sensitive=True),
              required=True)
def create(c, v, user, usergroup, perm):
    # Create the naming format for the tag permission
    perm_name = "{},{}".format(c, v)
    try:

        tag_uuid = 0
        for tag in tio.tags.list():

            tag_value = tag['value']
            tag_category = tag['category_name']
            if c == tag_category and v == tag_value:
                tag_uuid = tag['uuid']

        if user:
            user_id, uuid = get_user_id(user)
            resp = create_granular_permission(tag_name=perm_name, uuid=tag_uuid,
                                              perm_list=perm, perm_type="Tag", subject_type="User",
                                              subject_name=user, subject_uuid=uuid)
            pprint.pprint(resp)

        elif usergroup:
            group_id, uuid = get_group_id(usergroup)
            resp = create_granular_permission(tag_name=perm_name, uuid=tag_uuid,
                                              perm_list=perm, perm_type="Tag", subject_type="UserGroup",
                                              subject_name=usergroup, subject_uuid=uuid)
            pprint.pprint(resp)
        else:
            permission_response = create_permission(name=perm_name, tag_name=perm_name, uuid=tag_uuid,
                                                    perm_string=perm, perm_type="Tag", subject_type="AllUsers")

            pprint.pprint(permission_response)

    except IndexError:
        click.echo("\nYour Tag might be incorrect. Or you may need to update assets in navi.  "
                   "No tag UUID was returned\n")
        exit()


@access.command(help='Find all Tags without Permissions and apply "CanUse" permissions to AllUsers')
def migrate():
    click.confirm("\n This script finds all tags without any permissions and creates a CANUSE permission. "
                  "Do you want to continue?\n")
    unique_ids = []
    new_list_uuids = []

    # Grab all of the Tags with Can Use
    canuse_tags = grab_can_use_tags()

    # Grab all Tags and their names from the navi db
    tag_in_db = db_query("select tag_uuid, tag_key, tag_value from tags;")

    for tag in tag_in_db:
        # reduce the amount of tags uuids, since the navi db has a record for each asset:tag_uuid
        if tag[0] not in unique_ids:
            unique_ids.append(tag[0])
            # create a dict to hold the tag name and the tag uuid
            new_list_uuids.append({"{},{}".format(tag[1], tag[2]): tag[0]})

    # Loop through the list of uuids without permissions
    click.echo("\nCanUse permissions will be created for each of these tags\n")
    for uuid in new_list_uuids:
        for key in uuid:
            if uuid[key] not in canuse_tags:
                # Add permissions for each tag.

                print(str(key), str(uuid[key]))
                create_permission(name=key, tag_name=key, uuid=uuid[key], perm_string="CanUse", perm_type="Tag",
                                  subject_type="AllUsers")

    print()
