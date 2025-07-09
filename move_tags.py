import click
import pprint
from navi.plugins.api_wrapper import tenb_connection, request_data
from navi.plugins.database import db_query
from navi.plugins.enrich import tag_by_uuid
import textwrap

tio = tenb_connection()


@click.group(help="Move Scans, Users, and Tags to a new container")
def move():
    pass


@move.command(help="Move Tags from the Navi DB to a new container")
def dynamic():
    click.echo("\nMigrating Dyanmic Tags first\n")

    tags_to_move = db_query("select * from tagrules;")
    count = 0
    tag_list = []

    for tags in tags_to_move:
        c = tags[1]
        v = tags[3]
        d = tags[4]

        # The below code is shit but is needed due to how the data is saved
        new_filters = str(tags[6]).replace("property", "field")
        new_new_filters = str(new_filters).replace("wc", "match")
        super_new_filter = str(new_new_filters).replace("*", "")
        new_super_new_filter = str(super_new_filter).replace("operating_systems", "operating_system")
        filters1 = str(new_super_new_filter).replace("ipv4_addresses", "ipv4")
        filters2 = str(filters1).replace("ipv4_addresses", "ipv4")
        filters3 = str(filters2).replace("tags", "tag.Access Tags")
        filters4 = str(filters3).replace("name", "netbios_name")
        filters5 = str(filters4).replace("nwc", "nmatch")
        filters6 = str(filters5).replace("gt", "date-gt")
        filters7 = str(filters6).replace("lt", "date-lt")
        filters8 = str(filters7).replace("nexists", "set-hasnot")
        filters9 = str(filters8).replace("last_licensed_scan_time", "last_scan_time")
        filters10 = str(filters9).replace("fqdns", "fqdn")
        filters11 = str(filters10).replace("ports", "tag.Port")
        filters12 = str(filters11).replace("last_authenticated_scan_time", "Last Authenticated Scan")
        filters13 = str(filters12).replace("acr.score", "acr_score")

        filters = eval(filters13)

        try:

            payload = {"category_name": str(c), "value": str(v), "description": str(d), "filters": filters}
            pprint.pprint(payload)
            data = request_data('POST', '/tags/values', payload=payload)

            try:
                count += 1
                value_uuid = data["uuid"]
                cat_uuid = data['category_uuid']
                click.echo("\nI've created your new Tag - {} : {}\n".format(c, v))
                click.echo("The Category UUID is : {}\n".format(cat_uuid))
                click.echo("The Value UUID is : {}\n".format(value_uuid))
            except Exception as E:
                click.echo(E)
        except Exception as F:
            click.echo(F)

    click.echo("\nDynamic Tagging finished...Created {} tags!".format(count))


@move.command(help="Move Tags from the Navi DB to a new container")
@click.option("-v", is_flag=True, help="Print out all asset uuids")
def static(v):
    click.echo("\nGrabbing current Dynamic tag data from navi.db to skip.\n"
               "To migrate dynmaic tags use the 'navi move tags dynamic' command")
    tags_to_move = db_query("select * from tagrules;")
    tag_list = []
    for tags in tags_to_move:
        c = tags[1]
        v = tags[3]
        tag_list.append("{}:{}".format(c, v))

    click.echo("\nGrabbing Static Tag information\n")
    click.echo("*" * 100)
    tag_value = db_query("select distinct tag_uuid, tag_key, tag_value from tags")
    count = 0
    for tag in tag_value:
        if "{}:{}".format(tag[1], tag[2] not in tag_list):
            print("Tag Key and Value  - {} - {}".format(tag[1], tag[2]))

            data = db_query(
                "select uuid from assets LEFT JOIN tags ON uuid == asset_uuid where tag_uuid=='{}';".format(tag[0]))

            # Create a list of assets to tag
            new_asset_list = []

            for assets in data:
                count += 1
                new_asset_list.append(assets[0])
            tag_by_uuid(new_asset_list, "New-{}".format(tag[1]), "New-{}".format(tag[2]), d="Migrated by navi")
            if v:
                print(new_asset_list)
    click.echo("\nMigrated {} tags!\n".format(count))