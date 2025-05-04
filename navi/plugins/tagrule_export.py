import pprint
import click
from .api_wrapper import request_data
from .dbconfig import new_db_connection
from .database import insert_tag_rules


def export_tags():
    click.echo("\nCreating a new Table called 'tagrules' and saving Tag data for migration\n")
    tag_data = request_data("GET", "/tags/values")
    conn = new_db_connection("navi.db")
    with conn:
        count = 0
        evaluated = 0
        for tags in tag_data['values']:
            # Skip Static Tags
            evaluated += 1
            if str(tags['type']) == 'dynamic':
                count += 1
                # Grab the uuid to get the details; required to get the filters
                tag_uuid = tags['uuid']
                new_tag_data = request_data("GET", "/tags/values/{}".format(tag_uuid))

                # Grab data; make strings for easy storage.
                access = str(new_tag_data["access_control"])
                category_name = str(new_tag_data["category_name"])
                category_uuid = str(new_tag_data["category_uuid"])
                try:
                    description = str(new_tag_data['description'])
                except KeyError:
                    description = " "
                value = str(new_tag_data['value'])
                value_uuid = str(new_tag_data['uuid'])
                filters = str(new_tag_data['filters'])
                tag_value = [category_uuid, category_name, value_uuid, value, description, access, filters]
                print(tag_value)
                insert_tag_rules(conn, tag_value)

    click.echo("\nAll dynamic tags stored and static are skipped. "
               "Dynamic Tags Saved:{} out of a total: {}\n".format(count, evaluated))