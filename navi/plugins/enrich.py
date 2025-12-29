import click
import time
import csv
from .database import new_db_connection, db_query
from .api_wrapper import request_data, tenb_connection
from .tag_helper import update_tag, confirm_tag_exists, grab_all_tags, remove_tag
from sqlite3 import Error
import pprint
from datetime import datetime
from .add_by_file import add_helper
from .tag_helper import tag_checker
from collections import defaultdict
from .tone_tag_helper import tone_tag_by_uuid

tio = tenb_connection()


@click.group(help="Tag assets, Change ACR score by Tag, Add assets from other sources, "
                  "migrate tags from aws and assign attributes to assets")
def enrich():
    pass


def tag_by_tag(c, v, d, cv, cc, match):

    # BUG: Does not check to see if rule exists right now.
    # Start a blank rules list to store current a new tag rule.
    rules_list = []

    # Does the Parent Tag exist?
    parent_answer = confirm_tag_exists(c, v)

    # Is this the parent tag new or current?
    if parent_answer == 'yes':
        print("I found the parent")
        # Does the Child Tag Exist?
        child_answer = confirm_tag_exists(cc, cv)

        # Is the child tag new or current?
        if child_answer == 'yes':
            print("I found the child")
            # Update the tag parent tag with the new child tag
            click.echo("Your tag is being updated\n")

            try:

                # Need to grab the Tag UUID of our Parent Tag, so we can get more details
                tag_data = request_data('GET', '/tags/values')

                for value in tag_data['values']:
                    if str(value['category_name']).lower() == str(c).lower():
                        if str(value['value']).lower() == str(v).lower():
                            try:
                                tag_uuid = value['uuid']

                                # Get filter details
                                current_rule_set = request_data("GET", "/tags/values/" + tag_uuid)
                                print("Current Rule set")
                                pprint.pprint(current_rule_set)
                                print()

                                new_dict = eval(current_rule_set['filters']['asset'])
                                print(new_dict['and'])
                                rules_list = []

                                for val in new_dict['and']:
                                    print(val['value'][0])

                                '''
                                # The filter is a string in the API, pull out the dictionary representation and
                                filter_string = current_rule_set['filters']['asset']



                                # Turn the string into a dictionary
                                rule_set_dict = eval(filter_string)

                                print(rule_set_dict)

                                # Identify 'or' vs 'and' and set the current filter list to our 'rule_list'

                                '''
                            except Exception as F:
                                print("first error")
                                click.echo(F)

                payload = {"category_name": str(c), "value": str(v), "description": str(d),
                           "filters": {"asset": {str(match): rules_list}}}
                # Update the Parent Tag with the new child tag information
                print(payload)
                # data = request_data('PUT', '/tags/values/' + tag_uuid, payload=payload)

                # value_uuid = data["uuid"]
                # cat_uuid = data['category_uuid']
                # click.echo("\nI've Updated your Tag - {} : {}\n".format(c, v))
                # click.echo("The Category UUID is : {}\n".format(cat_uuid))
                # click.echo("The Value UUID is : {}\n".format(value_uuid))
            except Exception as E:
                print("Second error")
                click.echo(E)
        else:
            click.echo("The Child Tag does not exist")

    else:
        # If the parent tag doesn't exist, does the child?
        # Check to see if the child tag exists
        child_answer = confirm_tag_exists(cc, cv)
        if child_answer == 'yes':
            # if the child tag does exist, then create the new tag with the existing tag as a child
            try:
                payload = {"category_name": str(c), "value": str(v), "description": str(d),
                           "filters": {"asset": {str(match): [{"field": "tag.{}".format(cc),
                                                               "operator": "set-has", "value": str(cv)}]}}}
                data = request_data('POST', '/tags/values', payload=payload)

                value_uuid = data["uuid"]
                cat_uuid = data['category_uuid']
                click.echo("\nI've created your new Tag - {} : {}\n".format(c, v))
                click.echo("The Category UUID is : {}\n".format(cat_uuid))
                click.echo("The Value UUID is : {}\n".format(value_uuid))

            except Exception as F:
                click.echo(F)
        else:
            click.echo("Your Child Tag doesn't exist.\n You need to create a Child tag before adding it to a parent")


def tag_by_uuid(tag_list, c, v, d):
    tag_time = time.time()
    # Generator to split IPs into 2000 IP chunks

    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    # We Want to bail if the result is 0 Assets
    if not tag_list:
        click.echo("\nYour tag {}:{} resulted in 0 Assets, therefore the tag wasn't created\n".format(c, v))
        exit()
    elif tag_list == 'manual':
        # Create a blank Tag
        payload = {"category_name": str(c), "value": str(v), "description": str(d)}
        data = request_data('POST', '/tags/values', payload=payload)
        end_tag_time = time.time()
        value_uuid = data["uuid"]
        cat_uuid = data['category_uuid']
        click.echo("\nI've created your new Tag - {} : {}\n".format(c, v))
        click.echo("The Category UUID is : {}\n".format(cat_uuid))
        click.echo("The Value UUID is : {}\n".format(value_uuid))
        click.echo("Creation Time: {}".format(end_tag_time-tag_time))
    else:
        # Before updating confirm if the tag exists
        answer = confirm_tag_exists(c, v)

        # If the Tag does exist, update it by UUID.
        if answer == 'yes':
            # Check to see if the List of UUIDs is over 1999 (API Limit)
            if len(tag_list) > 1999:
                # break the list into 2000 IP chunks
                for chunks in chunks(tag_list, 1999):
                    update_tag(c, v, chunks)
            else:
                # If the Chunk is less than 2000, simply update it.
                update_tag(c, v, tag_list)
        # If the tag doesn't exist. we need to create one.
        else:
            # Create the Tag
            payload = {"category_name": str(c), "value": str(v), "description": str(d)}
            data = request_data('POST', '/tags/values', payload=payload)
            try:
                value_uuid = data["uuid"]
                cat_uuid = data['category_uuid']
                click.echo("\nI've created your new Tag - {} : {}\n".format(c, v))
                click.echo("The Category UUID is : {}\n".format(cat_uuid))
                click.echo("The Value UUID is : {}\n".format(value_uuid))
                end_tag_time = time.time()
                click.echo("New Tag Time: {}".format(end_tag_time - tag_time))
            except KeyError:
                click.echo("\nTag created but the uuid wasn't available\n")
                click.echo("Here is the payload navi sent: {}\n".format(payload))
            except TypeError:
                click.echo("*" * 100)
                click.echo("\n\nKNOWN ERROR CONDITION\n\n"
                           "This error occurs when you have the same tag category or tag value name\n"
                           "but it isn't exactly the same name. I.E name vs Name vs naMe\n"
                           "It could be missing a Capital letter or a space.\n"
                           "Try adding a 1 to your tag value and category to test this theory"
                           "report any other challenges to github\n"
                           "Disregard if you didn't get this error using navi tag or navi automate\n\n")
                click.echo("*" * 100)
                exit()
            # Check to see if the List of UUIDs is over 1999 (API Limit)
            if len(tag_list) > 1999:
                try:
                    click.echo("Your Tag list was over 2000 IPs.  "
                               "Splitting the UUIDs into chunks and updating the tags now")
                    # Break the UUIDs into Chunks and update the tag per chunk
                    for chunks in chunks(tag_list, 1999):
                        update_tag(c, v, chunks)

                except Exception as E:
                    click.echo("An Error Occurred: \n")
                    click.echo(E)
            else:
                try:
                    update_tag(c, v, tag_list)
                except Exception as E:
                    click.echo("An Error Occurred: \n")
                    click.echo(E)


def download_csv_by_plugin_id(scan_id, hist_id):
    # This is for scaling tagging by scan id
    filename = f'{scan_id}-report.csv'

    # Stream the report to disk
    with open(filename, 'wb') as fobj:
        tio.scans.export(scan_id, ('plugin.id', 'eq', '19506'),
                         format='csv', fobj=fobj, history_id=hist_id)
    return filename


def create_uuid_list(filename):
    from csv import DictReader
    uuids = []
    with open(filename) as fobj:
        for row in DictReader(fobj):
            asset_uuid = row['Asset UUID']
            if asset_uuid and asset_uuid != '':
                uuids.append(asset_uuid)
    return uuids


def remove_uuids_from_tag(tag_uuid):
    # Create a list to store our asset uuids
    asset_uuid_list = []

    tag_data = db_query("select asset_uuid from assets LEFT JOIN tags ON "
                        "uuid == asset_uuid where tag_uuid=='{}';".format(str(tag_uuid)))

    # Clean up the data into a list
    for asset_uuid_loop in tag_data:
        asset_uuid_list.append(asset_uuid_loop[0])

    # Generator to split IPs into 2000 IP chunks
    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    # Check to see if the List of UUIDs is over 1999 (API Limit)
    if len(asset_uuid_list) > 1999:

        # break the list into 2000 IP chunks
        for chunks in chunks(asset_uuid_list, 1999):
            remove_tag(str(tag_uuid), chunks)
    else:
        # If the Chunk is less than 2000, simply update it.
        remove_tag(str(tag_uuid), asset_uuid_list)


def download_tag_remove(scanid, new_hist, c, v, d):
    # Download a scan, tag assets by the scan id, remove the scan data.
    try:
        # To reduce API calls lets just download the csv
        filename = download_csv_by_plugin_id(scanid, new_hist)
        tag_list = create_uuid_list(filename)
        tag_by_uuid(tag_list, c, v, d)

        import os
        os.remove(filename)

    except TypeError:
        click.echo("Check the scan ID")
    except KeyError:
        click.echo("The scan used is archived, canceled, imported or aborted. Your Tag was not created.")


def organize_aws_keys(aws_ec2):
    aws_tags = {}  # Dictionary of Tag key/Value pairs
    aws_keys = {}  # Dictionary of Values/List of Instance Ids
    for tags in aws_ec2['Tags']:
        if tags['ResourceType'] == 'instance':
            aws_key = tags['Key']
            aws_value = tags['Value']
            resource_id = tags['ResourceId']

            # Tenable IO Requires a Key and a Value; AWS does not.  In this case we just use the key as both
            if aws_value == '':
                aws_value = aws_key

            # Creates a new value dict if one doesn't exist, adds to the value list if one does.
            try:
                aws_keys[aws_value].append(resource_id)
            except KeyError:
                aws_keys[aws_value] = [resource_id]

            # creates a key dict if one doesn't exist, adds the value dict if one does
            if aws_key not in aws_tags:
                aws_tags[aws_key] = {aws_value: aws_keys[aws_value]}
            else:
                aws_tags[aws_key].update({aws_value: aws_keys[aws_value]})

    return aws_tags


def get_attribute_uuid(name):
    attr_data = request_data('GET', '/api/v3/assets/attributes')
    uuid = 0
    for attr in attr_data['attributes']:
        if name == attr['name']:
            uuid = attr['id']

    return uuid


@enrich.group(help="Create and Assign Custom Attributes")
def attribute():
    pass

'''
@enrich.command(help="Create / Update / View Recast rules for 3rd party Data")
@click.option("--name", default=None, help="Recast Rule Name")
@click.option("--description", default="Created by navi", help="Recast Description")
@click.option("--expires_at", default=None, help="Expiration Date for Rule to expire")
@click.option("--new_severity", default="Low", help="New severity level")
@click.option("--query", default=None, help="Query for recast rule")
@click.option("--action", default=None, help="Recast")
def recast(name, query, description, expires_at, new_severity, action):
    create_recast_table()
    start = time.time()
    from .database import db_query_json_file
    #query = "select finding_id, asset_uuid, plugin_id, severity, cves from vulns where plugin_name != 'kernel';"
    recast_data = db_query(query)
    database = r"/tmp/navi.db"
    recast_conn = new_db_connection(database)
    recast_conn.execute('pragma journal_mode=wal;')
    recast_conn.execute('pragma synchronous=OFF')
    query_time_end = time.time()
    query_time = query_time_end - start
    print(query_time)
    with recast_conn:

        for assets in recast_data:
            recast_list = [assets[0], name, "HOST", expires_at, assets[1], assets[3], new_severity, action, description,
                           assets[2], assets[4], query]
            insert_recast(recast_conn, recast_list)

    insert_time_end = time.time()
    insert_time = insert_time_end - start
    print(insert_time)

    #db_query_json_file(table_name="recast",
                       #output_dir="/Users/creid/Documents/Code/navi_docker_containers/navi_services/Navi_tag_center/2123-1231-2122",
                       #chunk_size=10,
                       #new_directory="/Users/creid/Documents/Code/navi_docker_containers/navi_services/Navi_tag_center/2123-1231-2122")

'''


@enrich.command(help="Migrate AWS Tags to TVM tags by Instance ID")
@click.option("--region", default="", required=True, help="AWS Region")
@click.option("--a", default="", required=True, help="Access Key")
@click.option("--s", default="", required=True, help="Secret Key")
def migrate(region, a, s):
    import boto3
    if not a or not s or not region:
        click.echo("You need a region, access key and secret Key")
        exit()
    # Authentication
    ec2client = boto3.client('ec2', region_name=region, aws_access_key_id=a, aws_secret_access_key=s)

    # Grab All the tags in the Account
    aws_ec2 = ec2client.describe_tags()

    # Send the data to get organized into a neat dictionary of Lists
    aws_organized_tags = organize_aws_keys(aws_ec2)

    # Grab the Key, value and the new list out of the dict to send to the tagging function
    for key, value in aws_organized_tags.items():
        for z, w in value.items():
            uuid_list = []
            for instance in w:
                # Look up the UUID of the asset
                db = db_query("select uuid from assets where aws_id='{}';".format(instance))
                for record in db:
                    uuid_list.append(record[0])
            description = "AWS Tag by Navi"

            print("Creating a Tag named - {} : {} - with the following ids {}".format(key, z, w))

            tag_by_uuid(uuid_list, key, z, description)


@enrich.command(help="Create a Tag Category/Value Pair")
@click.option('--c', default=None, required=True, help="Create a Tag with the following Category name")
@click.option('--v', default=None, required=True,
              help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by navi', help="Description for your Tag")
@click.option('--cve', default='', help="Tag based on a CVE ID")
@click.option('--cpe', default='', help="Tag based on a CPE")
@click.option('--plugin', default='', help="Create a tag by plugin ID")
@click.option('--output', default='', help="Create a Tag based on the text in the output. "
                                           "Requires --plugin")
@click.option('--name', default='', help="Create a Tag by the text found in the Plugin Name")
@click.option('--group', default='', help="Create a Tag based on a Agent Group")
@click.option('--xrefs', default='', help="Tag by Cross References like CISA")
@click.option('--xid', '--xref-id', default='', help="Specify a Cross Reference ID")
@click.option("--route_id", default='', help='Tag assets by a Route ID in the vuln_route table.')
@click.option('--port', default='', help="Create a Tag based on "
                                         "Assets that have a vulnerability on a port.")
@click.option('--file', default='', help="Create a Tag based on IPs in a CSV file.")
@click.option('--scantime', default='', help="Create a Tag for assets that took longer "
                                             "than supplied minutes")
@click.option('--scanid', default='', help="Create a tag by Scan ID")
@click.option('--histid', default=None, help="Focus on a specific scan history; Requires --scanid")
@click.option('--query', default='', help="Use a custom query to create a tag.")
@click.option('--manual', default='', help="Tag assets manually by supplying the UUID")
@click.option('--missed', default='', help="Tag Agents that missed authentication in given number of days")
@click.option('--byadgroup', default='', help="Create Tags based on AD groups in a CSV")
@click.option('-regexp', is_flag=True, help="Use a Regular expression instead of a "
                                            "text search; requires another option")
@click.option("-tone", is_flag=True, help="Create TONE Tag instead of a TVM tag")
@click.option('--by_tag', default=None, help="Create a tag based off another Tag- 'category:value'")
@click.option('--by_cat', default=None, help="Create a tag by text or regexp in the value field "
                                             "of another tag or group of tags")
@click.option('--by_val', default=None, help="Create a tag by text or regexp in the catehgory field of "
                                             "another tag or group of tags")
@click.option('--cc', default='', help="Add a Tag to a new parent tag: Child Category")
@click.option('--cv', default='', help="Add a Tag to a new parent tag: Child Value")
@click.option('-all', is_flag=True, help="Change Default Match rule of 'or' to 'and' when creating "
                                         "parent/child tag relationships")
@click.option('-remove', is_flag=True, help="Remove this tag from all assets "
                                            "to support ephemeral asset tagging")
def tag(c, v, d, plugin, name, group, output, port, scantime, file, cc, cv, scanid, all, query, remove, cve, xrefs, xid,
        manual, histid, missed, byadgroup, regexp, route_id, tone, cpe, by_tag, by_cat, by_val):
    # start a blank list
    tag_list = []
    ip_list = ""
    by_tags_list = []

    if by_tag:
        # search for text in the tag, cat string
        try:
            category, value = str(by_tag).split(':')

        except ValueError:
            click.echo("\nEnsure your tag has a ':' or this feature won't work.  Category:Value\n")
            exit()

        by_tag_data = db_query("select asset_uuid from tags where tag_value == '{}' "
                               "and tag_key == '{}';".format(value, category))

        for assets in by_tag_data:
            by_tags_list.append(assets[0])

    if by_val:
        # search value
        if regexp:
            by_val_data = db_query("select asset_uuid from tags where tag_value REGEXP '{}';".format(by_val))
        else:
            by_val_data = db_query("select asset_uuid from tags where tag_value LIKE '%{}%';".format(by_val))

        for assets in by_val_data:
            by_tags_list.append(assets[0])

    if by_cat:
        # Search category
        if regexp:
            by_cat_data = db_query("select asset_uuid from tags where tag_key REGEXP '{}';".format(by_cat))
        else:
            by_cat_data = db_query("select asset_uuid from tags where tag_category LIKE '%{}%';".format(by_cat))

        for assets in by_cat_data:
            by_tags_list.append(assets[0])

    if output != '' and plugin == '':
        click.echo("You must supply a plugin")
        exit()

    if xid != '' and xrefs == '':
        click.echo("You must supply a Cross Reference Type using --xrefs option")

    if histid and not scanid:
        click.echo("You must supply a scan ID as well.")

    if plugin:
        d = d + "\nTag by Plugin ID: {}".format(plugin)
        try:
            if output:
                if regexp:
                    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns "
                                           "LEFT JOIN assets ON asset_uuid = uuid "
                                           "where plugin_id='{}' and output REGEXP '{}';".format(plugin, output))
                else:
                    plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns "
                                           "LEFT JOIN assets ON asset_uuid = uuid "
                                           "where plugin_id='{}' and output LIKE '%{}%';".format(plugin, output))
            else:
                plugin_data = db_query("SELECT asset_ip, asset_uuid, output "
                                       "from vulns where plugin_id={};".format(plugin))

            for x in plugin_data:
                auuid = x[1]
                # if by tags list isn't empty, Only add if the uuid is in the list.
                if by_tags_list:
                    if auuid in by_tags_list:
                        tag_list.append(auuid)
                else:
                    # To reduce duplicates check for the UUID in the list.
                    if auuid not in tag_list:
                        tag_list.append(auuid)
                    else:
                        pass
        except Error:
            pass

    if port != '':
        d = d + "\nTag by Port: {}".format(port)
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_uuid from vulns where port={};".format(port))

            data = cur.fetchall()

            try:
                for vulns in data:
                    uuid = vulns[0]
                    if by_tags_list:
                        if uuid in by_tags_list:
                            tag_list.append(uuid)
                    else:
                        # To reduce duplicates check for the UUID in the list.
                        if uuid not in tag_list:
                            tag_list.append(uuid)
            except ValueError:
                pass

    if name != '':
        d = d + "\nTag by Plugin Name: {}".format(name)
        try:

            if regexp:
                plugin_data = db_query("SELECT asset_ip, asset_uuid, output from vulns "
                                       "where plugin_name REGEXP '{}';".format(name))
            else:
                plugin_data = db_query("SELECT asset_ip, asset_uuid, output from vulns "
                                       "where plugin_name LIKE '%{}%';".format(name))

            for x in plugin_data:
                uuid = x[1]
                if by_tags_list:
                    if uuid in by_tags_list:
                        tag_list.append(uuid)
                else:
                    if uuid not in tag_list:
                        tag_list.append(uuid)
                    else:
                        pass
        except Error:
            pass

    if group != '':
        start_time = time.time()
        d = d + "\nTag by Agent Group: {}".format(group)
        try:
            group_id = None

            click.echo("\nGrabbing your Agent Group ID\n")
            try:

                group_data = request_data('GET', '/scanners/1/agent-groups')

                for agent_group in group_data['groups']:
                    # Grab each group name
                    group_name = agent_group['name']
                    # find the right name
                    if group_name == group:
                        group_id = agent_group['id']
                        click.echo("\nYour Group ID is {}\nGrabbing Agent data now\n".format(group_id))
                group_time = time.time()
                print(group_time - start_time)

            except IndexError:
                click.echo("\nClick your Group name was not found.  Check case and spelling and encase your "
                           "name in double quotes if it has special chars\n")
            try:
                plugin_data = db_query("select distinct(asset_uuid) from agents where groups like '%{}%';".format(group_id))
                try:
                    for x in plugin_data:
                        uuid = x[0]
                        if by_tags_list:
                            if uuid in by_tags_list:
                                tag_list.append(uuid)
                        else:
                            tag_list.append(uuid)

                except TypeError:
                    click.echo("You Tag resulted in 0 Assets; so a tag wasn't created."
                               "\nMake sure you have run 'navi config update agents'")
            except IndexError:
                click.echo("\nCheck your API permissions\n")
        except Error:
            click.echo("You might not have agent groups, or you are using Nessus Manager.  ")
        print("Number of Assets being tagged: {}".format(len(tag_list)))

    if scantime != '':
        d = d + "\nThis asset was tagged because the scan time took over {} mins".format(scantime)
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id='19506';")

            data = cur.fetchall()
            try:
                for vulns in data:
                    plugin_dict = {}
                    plugin_output = vulns[2]

                    # split the output by return
                    parsed_output = plugin_output.split("\n")

                    for info_line in parsed_output:
                        try:
                            new_split = info_line.split(" : ")
                            plugin_dict[new_split[0]] = new_split[1]

                        except IndexError:
                            pass
                    try:
                        intial_seconds = plugin_dict['Scan duration']
                    except KeyError:
                        intial_seconds = 'unknown'

                    # For an unknown reason, the scanner will print unknown for some assets
                    # leaving no way to calculate the time.
                    if intial_seconds != 'unknown':

                        # Numerical value in seconds parsed from the plugin
                        try:
                            seconds = int(intial_seconds[:-3])
                            minutes = seconds / 60
                        except ValueError:
                            minutes = 0

                        # grab assets that match the criteria
                        if minutes > int(scantime):
                            try:
                                ip_list = ip_list + "," + str(vulns[0])
                                tag_list.append(vulns[1])
                            except ValueError:
                                pass
                click.echo()
            except ValueError:
                pass

    if file != '':
        d = d + "\nTagged using IPs found in a file named:{}".format(file)
        with open(file, 'r', newline='') as new_file:
            add_ips = csv.reader(new_file)

            for row in add_ips:
                for ips in row:
                    # need to look grab UUIDS per IP for the ablity to update Tags
                    tag_list.append(ips)

        uuid_list = []
        for assets in tag_list:
            asset_uuid = db_query("select distinct asset_uuid from vulns where asset_ip='{}'".format(assets.strip()))
            if asset_uuid:
                uuid_list.append(asset_uuid[0][0])

        if tone:
            tone_tag_by_uuid(tag_list, c, v, d)
        else:
            tag_by_uuid(tag_list, c, v, d)

    if cv != '' and cc != '':

        if all:
            match = 'and'
            tag_by_tag(c, v, d, cv, cc, match)
        else:
            match = 'or'
            tag_by_tag(c, v, d, cv, cc, match)

    if scanid:
        d = d + "\nTag by Scan ID: {}".format(scanid)
        tag_list = []
        if histid:
            download_tag_remove(scanid, histid, c, v, d)
        else:
            try:
                scandata = request_data('GET', '/scans/' + str(scanid))

                status = scandata['history'][0]['status']

                if status == 'completed':
                    try:
                        for host in scandata['hosts']:
                            tag_list.append(host['uuid'])

                        # This method is to get around the 5000 row return limit in IO.
                        if len(tag_list) >= 4999:

                            click.echo("\nYou're scan is 5000 IPs or More. Downloading, Parsing and Cleaning up scans "
                                       "to ensure all assets are tagged\n")
                            click.echo("\nTags can take a few minutes to populate in the UI when applied to "
                                       "1000s of assets\n")
                            hist_id = scandata['history'][0]['history_id']
                            download_tag_remove(scanid, hist_id, c, v, d)
                        else:
                            # Scans under 5000 would just use the current tag_list
                            tag_by_uuid(tag_list, c, v, d)
                    except TypeError:
                        click.echo("Check the scan ID")
                    except KeyError:
                        click.echo("The scan used is archived, canceled, imported or aborted. "
                                   "Your Tag was not created.")
                else:
                    # cycle through history until you reach completed
                    hist = 1
                    new_hist = 0

                    # if you got here the first scan has not completed
                    while status != 'completed':
                        # call the scan history again to check the next Status
                        # continue to do so until one says completed
                        new_scan_data = request_data('GET', '/scans/' + str(scanid))
                        status = new_scan_data['history'][hist]['status']

                        # Grab the history of the completed asset
                        new_hist = new_scan_data['history'][hist]['history_id']

                        # To limit the amount of called to a minimum
                        # Use a while loop and increase the history ID by 1 until completed is found
                        hist = hist + 1

                    download_tag_remove(scanid, new_hist, c, v, d)

            except IndexError:
                click.echo("\nThe scan used is archived, canceled, imported or aborted "
                           "and has no completed scans in it's history\n")
            except Exception as E:
                click.echo("Check your Scan ID; An Error occurred\n{}".format(E))

    if query:
        d = d + "\nTag by SQL Query: \n{}".format(query)
        try:
            data = db_query(query)

            for asset in set(data):
                tag_list.append(asset[0])

            if tone:
                tone_tag_by_uuid(tag_list, c, v, d)
            else:
                tag_by_uuid(tag_list, c, v, d)
        except (KeyError, IndexError):
            click.echo("\nSomething went wrong")

    if remove:
        # Find the UUID of our given tag
        tag_list = grab_all_tags()
        try:

            for tag_info in tag_list:
                # Grab our UUID
                if str(tag_info[0]).lower() == str(c).lower():
                    if str(tag_info[1]).lower() == str(v).lower():
                        new_uuid = str(tag_info[2])
                        print("grab all tags, find correct uuid, hit db with {}".format(new_uuid))
                        remove_uuids_from_tag(new_uuid)

        except Exception as E:
            click.echo(E)

    if cve:
        d = d + "\nTag by CVE ID: {}".format(cve)
        if len(cve) < 10:
            click.echo("\nThis is likely not a CVE...Try again...\n")

        elif "CVE" not in cve:
            click.echo("\nYou must have 'CVE' in your CVE string. EX: CVE-1111-2222\n")

        else:
            plugin_data = db_query("SELECT asset_uuid from vulns where cves LIKE '%" + cve + "%';")

            for x in plugin_data:
                uuid = x[0]
                if by_tags_list:
                    if uuid in by_tags_list:
                        tag_list.append(uuid)
                else:
                    if uuid not in tag_list:
                        tag_list.append(uuid)

                    else:
                        pass

    if cpe:
        d = d + "\nTag by CPE: {}".format(cpe)
        if regexp:
            assets_by_cpe = db_query("select distinct(asset_uuid) from cpes where cpe_string REGEXP '{}'".format(cpe))
        else:
            assets_by_cpe = db_query("select distinct(asset_uuid) from cpes where cpe_string LIKE '%" + cpe + "%'")

        for asset_uuids in assets_by_cpe:
            asset_uuid = asset_uuids[0]
            if by_tags_list:
                if asset_uuid in by_tags_list:
                    tag_list.append(asset_uuid)
            else:
                if asset_uuid not in tag_list:
                    tag_list.append(asset_uuid)

    if xrefs:
        d = d + "\nTag by Cross Reference: {}".format(xrefs)
        if xid:
            d = d + "\n Refined tag search to the follow Cross Reference ID text search: {}".format(xid)
            xref_data = db_query("select asset_uuid from vulns where "
                                 "xrefs LIKE '%{}%' AND xrefs LIKE '%{}%'".format(xrefs, xid))

        else:
            if regexp:
                xref_data = db_query("select asset_uuid from vulns where xrefs REGEXP '{}'".format(xrefs))
            else:
                xref_data = db_query("select asset_uuid from vulns where xrefs LIKE '%{}%'".format(xrefs))

        for x in xref_data:
            uuid = x[0]
            if by_tags_list:
                if uuid in by_tags_list:
                    tag_list.append(uuid)
            else:
                if uuid not in tag_list:
                    tag_list.append(uuid)
                else:
                    pass

    if manual:
        tag_list.append(manual)
        if tone:
            tone_tag_by_uuid(tag_list, c, v, d)
        else:
            tag_by_uuid(tag_list, c, v, d)

    if missed:
        try:
            missed_data = db_query("select uuid, last_licensed_scan_date from assets where agent_uuid !='None';")

            for assets in missed_data:
                last_scanned_date = assets[1]

                new_date = datetime.fromisoformat(last_scanned_date[:-1])

                today = datetime.utcnow()
                delta = today - new_date

                if delta.days >= int(missed):
                    tag_list.append(assets[0])

            if tone:
                tone_tag_by_uuid(tag_list, c, v, d)
            else:
                tag_by_uuid(tag_list, c, v, d)

        except IndexError:
            click.echo("\nMake sure you are submitting an Integer\n")
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    if byadgroup:
        # 'HFAUsersWithDevices.csv'
        filename = byadgroup
        new_list = []
        # Open the AD csv file
        with open(filename, newline='') as csvfile:
            # Use dict reader to pull a particular column
            hfa_reader = csv.DictReader(csvfile)
            # Cycle through each row
            for row in hfa_reader:
                # Pull the OU out of the DN column
                dname = str(row['DistinguishedName']).split("OU=")[2]

                # Grab the hostname of the primary device
                new_list.append(row['PrimaryDevice1'])

                # Check to see if there is a secondary device
                try:
                    if str(row["PrimaryDevice2"]):
                        new_list.append(row['PrimaryDevice2'])
                except KeyError:
                    pass
        # Create the dictionary
        hfa_dict = {"{}".format(dname[:-1]): new_list}

        # Gab hostnames and UUIDs
        data = db_query("select asset_uuid, output from vulns where plugin_id='55472'")

        clean_hostname_list = []
        for hostnames in data:
            hostname = hostnames[1].split("\n")[1].split(":")[1]
            uuid = hostnames[0]
            clean_hostname_list.append([hostname, uuid])

        for key, value in hfa_dict.items():
            print(key)
            # gather uuids to tag
            tag_list = []
            for v in value:
                for x in clean_hostname_list:

                    if v in x[0]:
                        print("tag --c AD Groups --v {}".format(key))
                        tag_list.append(x[1])
            tag_by_uuid(tag_list, c="AD Groups", v=key, d="AD Groups tagged by navi")

    if route_id:
        route_info = db_query("select plugin_list from vuln_route where route_id='{}'".format(route_id))

        work = str(route_info[0][0]).replace("[", "(").replace("]", ")")

        vulns_to_route = db_query("select assets.uuid from assets left join vulns on assets.uuid = vulns.asset_uuid "
                                  "where vulns.plugin_id in {} and vulns.severity !='info';".format(work))

        for assets in vulns_to_route:
            if by_tags_list:
                if assets in by_tags_list:
                    tag_list.append(assets)
            else:
                tag_list.append(assets[0])

    if tone:
        tone_tag_by_uuid(tag_list, c, v, d)
    else:
        tag_by_uuid(tag_list, c, v, d)


@enrich.command(help="Create Tag rules in tenable VM")
@click.option('--c', default='', help="Create a Tag with the following Category name")
@click.option('--v', default='', help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by navi', help="Description for your Tag")
@click.option('--filter', default='', help="Filter used to tag assets")
@click.option('--action', default='', help="Type of operator")
@click.option('--value', default='', help="Filter value")
@click.option('--multi', default='', help="A well crafted pytenable list of tuples")
@click.option('--file', default='', help="Create a tag rule by IP addresses found in a CSV")
@click.option('-any', is_flag=True, help="Change the default from 'and' to 'or")
def tagrule(c, v, filter, action, value, d, multi, any, file):
    if c == '':
        click.echo("Category is required.  Please use the --c command")
        exit()

    if v == '':
        click.echo("Value is required. Please use the --v command")
        exit()

    if multi == '' and filter == '' and file == '':
        click.echo("\nYou need to select an individual 'filter' or 'multi' for multiple filters\n")
        exit()

    if multi:
        try:
            click.echo("creating a new tag with the following list {}".format(multi))
            filter_list = []
            for os in eval(multi):
                temp_dict = {"field": os[0], "operator": os[1], "value": os[2]}
                filter_list.append(temp_dict)
                # issue with tenable VM API - Or turns in to a string value seperated by a comma
                # issue with tenable VM API - appends " when you add * so *centos* becomes "*centos*"
            if any:
                tio.tags.create(c, v, filters=eval(multi), filter_type="or", description=d)
            else:
                tio.tags.create(c, v, filters=eval(multi), description=d)
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    if filter:
        try:
            if action:
                if value:
                    rule_tuple = (filter, action, [value])
                    try:
                        tio.tags.create(c, v, filters=[rule_tuple], description=d)
                    except Exception as E:
                        click.echo(E)
                        click.echo("\nThis tag name already exist; Delete it or rename the one you want to create.\n")
                else:
                    click.echo("You must have a value if you are going to use a filter")
                exit()
            else:
                click.echo("You must have an Action if you are going to use a filter")
                exit()
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    if file:
        # API will limit this by 1024 - need a counter
        ip_list = ''
        for_length = []
        if file != '':
            d = d + "\nTagged using IPs found in a file named:{}".format(file)
            with open(file, 'r', newline='') as new_file:
                add_ips = csv.reader(new_file)

                for row in add_ips:
                    for ips in row:
                        ip_list = ip_list + "," + ips
                        for_length.append(ips)
        try:
            payload = {"category_name": str(c), "value": str(v), "description": str(d),
                       "filters": {"asset": {"and": [{"field": "ipv4",
                                                      "operator": "eq", "value": [str(ip_list[1:])]}]}}}
            data = request_data('POST', '/tags/values', payload=payload)
            try:
                value_uuid = data["uuid"]
                cat_uuid = data['category_uuid']
                click.echo("\nI've created your new Tag - {} : {}\n".format(c, v))
                click.echo("The Category UUID is : {}\n".format(cat_uuid))
                click.echo("The Value UUID is : {}\n".format(value_uuid))
                click.echo("{} IPs added to the Tag".format(str(len(for_length))))
            except Exception as E:
                click.echo(E)
        except Exception as F:
            click.echo("\nEnsure your IP list is not more than 1024.  If so, use the 'navi add' command")
            click.echo("This will add each IP in the list. Then run 'navi update assets'")
            click.echo("Finally, use the tag --file option to tag known IPs in the navi.db")
            click.echo(F)


@enrich.command(help="Adjust ACRs in Tenable One by tag")
@click.option('--score', default='', help='Set the ACR score')
@click.option('--mod', required=True, type=click.Choice(['set', 'inc', 'dec'], case_sensitive=True),
              multiple=False, help="Increases/Decreases or Sets the ACR value")
@click.option('--c', default=None, required=True,  help="Tag Category to use")
@click.option('--v', default=None, required=True, help="Tag Value to use")
@click.option('--note', default="navi Generated", help="Enter a Note to your ACR update")
@click.option('-business', '-b', is_flag=True, help="Add Business Critical To ACR Change Reason(s)")
@click.option('-compliance', '-c', is_flag=True, help="Add Compliance To ACR Change Reason(s)")
@click.option('-mitigation', '-m', is_flag=True, help="Add Mitigation Controls To ACR Change Reason(s)")
@click.option('-development', '-d', is_flag=True, help="Add Development To ACR Change Reason(s)")
def acr(score, v, c, note, business,  compliance, mitigation, development, mod):
    choice = []

    if business:
        choice.append("Business Critical")

    if compliance:
        choice.append("In Scope For Compliance")

    if mitigation:
        choice.append("Existing Mitigation Control")

    if development:
        choice.append("Dev Only")

    if not business and not mitigation and not compliance and not development:
        choice.append("Key Drivers does not match")

    if note != 'navi Generated':
        choice.append("Other")

    if int(score) in range(1, 11):
        try:
            acr_dict = defaultdict(list)

            data = db_query("select acr, asset_uuid from tags left join assets on assets.uuid = tags.asset_uuid "
                            "where tag_key='{}' and tag_value='{}';".format(c, v))

            # create a list of all UUIDs associated; this will be used for comparison later
            allow_list = []
            for asset in data:
                uuid = asset[1]
                # First make sure the asset doesn't have a NO:UPDATE tag
                check_for_no = tag_checker(uuid, "NO", "UPDATE")
                if check_for_no == 'no':
                    allow_list.append(uuid)

            for rate, uuid in data:
                # ensure the UUID is in the 'allow_list'
                if uuid in allow_list:
                    acr_dict[rate].append(uuid)

            for keys in acr_dict:
                current_acr = keys
                asset_list = []
                for uuid in acr_dict[keys]:
                    asset_list.append({"id": uuid})

                try:
                    if current_acr:
                        # avoid trying to update assets with "None"
                        if mod == 'set':
                            new_acr = score
                        elif mod == 'inc':
                            new_acr = int(current_acr) + int(score)
                            if new_acr > 10:
                                new_acr = 10
                        elif mod == 'dec':
                            new_acr = int(current_acr) - int(score)
                            if new_acr < 1:
                                new_acr = 1
                        else:
                            pass

                        # check to see if the list goes over 1999 assets then chunk the requests.
                        def chunks(l, n):
                            for i in range(0, len(l), n):
                                yield l[i:i + n]

                        if len(asset_list) > 1999:
                            click.echo("Your request was over 1999 assets and "
                                       "therefore will be chunked up in to groups of "
                                       "1999. You will see a 'success' message per chunk.")
                            for chunks in chunks(asset_list, 1999):
                                lumin_payload = [{"acr_score": int(new_acr),
                                                  "reason": choice, "note": note, "asset": chunks}]
                                request_data('POST', '/api/v2/assets/bulk-jobs/acr',
                                             payload=lumin_payload)
                        else:
                            click.echo("\nProcessing your ACR update requests\n")
                            lumin_payload = [{"acr_score": int(new_acr),
                                              "reason": choice, "note": note, "asset": asset_list}]
                            request_data('POST', '/api/v2/assets/bulk-jobs/acr',
                                         payload=lumin_payload)
                except TypeError:
                    pass
        except TypeError:
            click.echo("\nCheck your API Keys or permissions\n")

    else:
        click.echo("\nYou can't have a score below 1 or higher than 10\n")


@attribute.command(help="Create an Custom Attribute")
@click.argument('name')
@click.option('--description', default='', help="Add a description for clarity")
def create(name, description):
    try:
        payload = {"attributes": [
            {
                "name": name,
                "description": "{} -Updated by Navi".format(description)
            }
        ]}
        create_data = request_data('POST', '/api/v3/assets/attributes', payload=payload)
        click.echo(create_data)
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@attribute.command(help="Add a custom attribute to an asset")
@click.option('--uuid', default='', help="UUID of the asset")
@click.option('--name', default='', help="Name of the Custom Attribute")
@click.option('--value', default='', help="Value of the Custom Attribute")
def assign(uuid, name, value):
    try:
        attr_uuid = get_attribute_uuid(name)
        click.echo(attr_uuid)
        payload = {"attributes": [
            {
                "value": value,
                "id": attr_uuid
            }
        ]}
        assign_attr = request_data("PUT", '/api/v3/assets/{}/attributes'.format(uuid), payload=payload)
        click.echo(assign_attr)
    except TypeError:
        click.echo("\nCheck your API Keys or permissions\n")


@enrich.command(help="Add an asset to tenable VM from another source via CLI")
@click.option('--ip', default='', help="IP address of the new asset")
@click.option('--mac', default='', help="Mac Address of the new asset")
@click.option('--netbios', default='', help="NetBios of the new asset")
@click.option('--fqdn', default='', help='FQDN of the new asset')
@click.option('--hostname', default='', help="Hostname of the new asset")
@click.option('--file', default='', help="Provide a CSV file in this order: IP, MAC, FQDN, Hostname. "
                                         "Leave fields blank if N/A")
@click.option('--source', default='navi', help="Provide the source of the information")
def add(ip, mac, netbios, fqdn, hostname, file, source):
    try:
        asset = {}
        ipv4 = []
        macs = []
        fqdns = []
        hostnames = []
        if ip:
            ipv4.append(ip)
            asset["ip_address"] = ipv4

        if mac:
            macs.append(mac)
            asset["mac_address"] = macs

        if netbios:
            asset["netbios_name"] = netbios

        if fqdn:
            fqdns.append(fqdn)
            asset["fqdn"] = fqdns

        if hostname:
            hostnames.append(hostname)
            asset["hostname"] = hostnames

        if file:
            add_helper(file, source)

        if asset:
            # create Payload
            payload = {"assets": [asset], "source": source}

            click.echo("Adding the following Data : \n{}\n".format(payload))

            # request Import Job
            data = request_data('POST', '/import/assets', payload=payload)
            click.echo("Your Import ID is : {}".format(data['asset_import_job_uuid']))
        else:
            click.echo("\nPlease enter an some information. Use '--help' for more info\n")

    except Error:
        click.echo("\nCheck your permissions or your API keys\n")
    except TypeError:
        click.echo("\nCheck your permissions or your API keys\n")
