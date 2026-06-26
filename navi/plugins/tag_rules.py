from os import system as sys
import click
from .database import db_query


from .api_wrapper import tenb_connection, request_data
from .database import db_query
import time
import json
import base64

tio = tenb_connection()
time_now = time.time()


def create_tag_magic_url(uuid):
    # craft url for specific uuid
    url_base = ('https://cloud.tenable.com/tio/app.html#/'
                'assets-uw/all-assets/list?s=&uw_all_assets_list.st=last_observed.1&f=')
    pre_tag_filter = [{"id": "tags", "operator": "eq", "value": ["{}".format(uuid)]}]

    # Turn the list into json
    filter_list = json.dumps(pre_tag_filter)

    # Encode the json list into base64
    base64_filter = base64.b64encode(filter_list.encode('ascii'))

    # build the 3 part URL
    full_url = "{}{}".format(url_base, base64_filter.decode('UTF-8'))

    return full_url


for tag in tio.tags.list():
    tag_uuid = tag['uuid']
    tag_cat = tag['category_name']
    tag_val = tag['value']
    magic_url = create_tag_magic_url(tag_uuid)
    data = db_query("UPDATE rules SET uuid = '{}', run_date='{}', magic_url = '{}' where category = '{}' "
                    "AND value = '{}';".format(tag_uuid,time_now, magic_url, tag_cat, tag_val))

data = db_query("select * from rules;")


def run_rules_now():
    rule_data = db_query("select * from rules;")

    for rule in rule_data:
        if rule[3] == 'plugin_id':
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --plugin {}".format(rule[1], rule[2], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --plugin {}".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'plugin_name':
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --name \"{}\"".format(rule[1], rule[2], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --name \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'plugin_output':
            # Do later: Condition might be to look at all plugins or a specfic one
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --plugin {} --output {}".format(rule[1], rule[2], rule[5], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --plugin {} --output \"{}\"".format(rule[1], rule[2], rule[5], rule[4]))

        elif rule[3] == 'cve':
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --cve {}".format(rule[1], rule[2], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --cve \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'xref':

            if rule[5] != "":
                click.echo("navi enrich tag --c \"{}\" --v \"{}\" --xref {} --xid {}".format(rule[1], rule[2], rule[4], rule[5]))
                sys("navi enrich tag --c \"{}\" --v \"{}\" --xref \"{}\" --xid \"{}\"".format(rule[1], rule[2], rule[4], rule[5]))

            else:
                click.echo("navi enrich tag --c \"{}\" --v \"{}\" --xref {}".format(rule[1], rule[2], rule[4]))
                sys("navi enrich tag --c \"{}\" --v \"{}\" --xref \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'group':
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --group {}".format(rule[1], rule[2], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --group \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'scantime':
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --scantime {}".format(rule[1], rule[2], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --scantime \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'scanid':
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --scanid {}".format(rule[1], rule[2], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --scanid \"{}\"".format(rule[1], rule[2], rule[4]))

        elif rule[3] == 'ports':
            click.echo("navi enrich tag --c \"{}\" --v \"{}\" --port {}".format(rule[1], rule[2], rule[4]))
            sys("navi enrich tag --c \"{}\" --v \"{}\" --port \"{}\"".format(rule[1], rule[2], rule[4]))

        else:
            click.echo("{} not currently supported".format(rule[3]))