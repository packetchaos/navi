import click
from .database import db_query
from .api_wrapper import request_data, tenb_connection


tio = tenb_connection()
'''
1 - Retrieve all Permissions in the container
    a. Filter this list down to the ones including the CanUse action
    b. Extract all unique Tag uuids from the object field of the filtered Permission list
2. Retrieve all Tags in the container
    a. Filter this list down to the ones whose uuids are not in the list produced in 1b
    b. Create a new Permission with AllUsers group as the subject, CanUse as the action, and the Tag as the object
'''


def create_permission(name, uuid):
    payload = {
        "actions": ["CanUse"],
        "objects": [
            {
                "name": name,
                "type": "Tag",
                "uuid": str(uuid)
            }
        ],
        "subjects": [{"type": "AllUsers"}],
        "name": "{} [CANUSE]".format(name)
    }
    response = request_data("POST", "/api/v3/access-control/permissions", payload=payload)
    return response


def grab_can_use_tags():
    data = request_data("GET", "/api/v3/access-control/permissions")

    #pprint.pprint(data['permissions'])
    list_of_tag_uuids = []
    #Filter on just permissions
    for perms in data['permissions']:
        # Need to search for CanView
        if 'CanUse' in str(perms['actions']):

            # Extract all Tag UUIDs
            #pprint.pprint(perms['objects'])
            for tag in perms['objects']:
                try:
                    #print(tag['type'])
                    if tag['type'] == 'Tag':
                        #print(tag['uuid'])
                        list_of_tag_uuids.append(tag['uuid'])
                except KeyError:
                    pass
    return list_of_tag_uuids


@click.command(help="Bulk Change Permissions")
def access():
    click.confirm("\n This script finds all tags without any permissions and creates a CANUSE permission. Do you want to continue?\n")
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
                create_permission(key, uuid[key])

    print()
