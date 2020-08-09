import click
import csv
from .database import new_db_connection
from .api_wrapper import request_data, request_delete
from .tag_helper import update_tag, confirm_tag_exists, return_tag_uuid
from sqlite3 import Error


@click.command(help="Create a Tag Category/Value Pair")
@click.option('--c', default='', help="Create a Tag with the following Category name")
@click.option('--v', default='', help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by navi', help="Description for your Tag")
@click.option('--plugin', default='', help="Create a tag by plugin ID")
@click.option('--name', default='', help="Create a Tag by the text found in the Plugin Name")
@click.option('--group', default='', help="Create a Tag based on a Agent Group - BY IP Due To API BUG")
@click.option('--output', default='', help="Create a Tag based on the text in the output. Requires --plugin")
@click.option('--port', default='', help="Create a Tag based on Assets that have a port open.")
@click.option('--file', default='', help="Create a Tag based on IPs in a CSV file.")
@click.option('--scantime', default='', help="Create a Tag for assets that took longer than supplied minutes")
def tag(c, v, d, plugin, name, group, output, port, scantime, file):
    # Generator to split IPs into 2000 IP chunks
    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    # start a blank list; IP list is due to a bug
    tag_list = []
    ip_list = ""
    ip_update = 0

    if c == '':
        print("Category is required.  Please use the --c command")
        exit()

    if v == '':
        print("Value is required. Please use the --v command")
        exit()

    if output != '' and plugin == '':
        print("You must supply a plugin")
        exit()

    if plugin:
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                # See if we want to refine our search by the output found in this plugin
                # this needs to have a JOIN statement to reduce the amount
                if output != "":
                    cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id='" + plugin + "' and output LIKE '%" + output + "%';")
                else:
                    cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id=%s;" % plugin)

                plugin_data = cur.fetchall()
                for x in plugin_data:
                    ip = x[0]
                    uuid = x[1]
                    # To reduce duplicates check for the UUID in the list.
                    if uuid not in tag_list:
                        tag_list.append(uuid)
                        ip_list = ip_list + "," + ip
                    else:
                        pass
        except Error:
            pass

    if port != '':
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * from vulns where port=" + port + " and (plugin_id='11219' or plugin_id='14272' or plugin_id='14274' or plugin_id='34220' or plugin_id='10335');")

            data = cur.fetchall()

            try:
                for vulns in data:
                    ip = vulns[1]
                    uuid = vulns[2]
                    # To reduce duplicates check for the UUID in the list.
                    if uuid not in tag_list:
                        tag_list.append(uuid)
                        ip_list = ip_list + "," + ip
            except ValueError:
                pass

    if name != '':
        try:
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_name LIKE '%" + name + "%';")

                plugin_data = cur.fetchall()
                for x in plugin_data:
                    ip = x[0]
                    uuid = x[1]
                    if uuid not in tag_list:
                        tag_list.append(uuid)
                        ip_list = ip_list + "," + ip
                    else:
                        pass
        except Error:
            pass

    if group != '':
        ip_update = 1
        print("\nDue to a API bug, I'm going to delete the current tag. You may get a 404 error if this is a new tag.")
        # Updating tags is only allowed via tenable ID(UUID); However you can't grab the UUID from the Agent URI
        # Need to research a better solution for this problem.  Need to submit a bug.  Going to just delete the tag for now.
        uuid_to_delete = return_tag_uuid(c, v)
        request_delete('DELETE', '/tags/values/' + str(uuid_to_delete))
        try:
            querystring = {"limit": "5000"}
            group_data = request_data('GET', '/scanners/1/agent-groups')
            for agent_group in group_data['groups']:
                group_name = agent_group['name']
                group_id = agent_group['id']

                if group_name == group:
                    data = request_data('GET', '/scanners/1/agent-groups/' + str(group_id) + '/agents', params=querystring)
                    ip_list = ''

                    for agent in data['agents']:
                        ip_address = agent['ip']
                        uuid = agent['uuid']
                        ip_list = ip_list + "," + ip_address
                        tag_list.append(uuid)
        except Error:
            print("You might not have agent groups, or you are using Nessus Manager.  ")

    if scantime != '':
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id='19506';")

            data = cur.fetchall()
            try:
                for vulns in data:

                    output = vulns[2]

                    # split the output by return
                    parsed_output = output.split("\n")

                    # grab the length so we can grab the seconds
                    length = len(parsed_output)

                    # grab the scan duration- second to the last variable
                    duration = parsed_output[length - 2]

                    # Split at the colon to grab the numerical value
                    seconds = duration.split(" : ")

                    # split to remove "secs"
                    number = seconds[1].split(" ")

                    # grab the number for our minute calculation
                    final_number = number[0]

                    # convert seconds into minutes
                    minutes = int(final_number) / 60

                    # grab assets that match the criteria
                    if minutes > int(scantime):
                        try:
                            ip_list = ip_list + "," + str(vulns[0])
                            tag_list.append(vulns[1])
                        except ValueError:
                            pass
                print()
            except ValueError:
                pass

    if file != '':
        ip_update = 1
        with open(file, 'r', newline='') as new_file:
            add_ips = csv.reader(new_file)

            for row in add_ips:
                for ips in row:
                    # need to look grab UUIDS per IP for the ablity to update Tags
                    tag_list.append(ips)
                    ip_list = ip_list + "," + ips

    if ip_list == '':
        print("\nYour tag resulted in 0 Assets, therefore the tag wasn't created\n")
        exit()
    else:
        # Before updating confirm if the tag exists
        answer = confirm_tag_exists(c, v)

        # If the Tag does exist, update it.
        if answer == 'yes':
            if len(tag_list) > 1999:
                # break the list into 2000 IP chunks
                for chunks in chunks(tag_list, 1999):
                    update_tag(c, v, chunks)
            else:
                # If the Chunk is less than 2000, simply update it.
                update_tag(c, v, tag_list)
        else:
            # If the tag doesn't exist. we need to create one.
            if len(tag_list) > 1999:
                try:
                    # Create the Tag
                    payload = {"category_name": str(c), "value": str(v), "description": str(d)}
                    data = request_data('POST', '/tags/values', payload=payload)
                    value_uuid = data["uuid"]
                    cat_uuid = data['category_uuid']
                    print("\nI've created your new Tag - {} : {}\n".format(c, v))
                    print("The Category UUID is : {}\n".format(cat_uuid))
                    print("The Value UUID is : {}\n".format(value_uuid))
                    print("Your Tag list was over 2000 IPs.  Splitting the UUIDs into chunks and updating the tags now")
                    # Break the UUIDs into Chunks and update the tag per chunk
                    for chunks in chunks(tag_list, 1999):
                        update_tag(c, v, chunks)

                    print(str(len(tag_list)) + " UUIDs added to the Tag")
                except Exception as E:
                    print("Duplicate Tag Category: You may need to delete your tag first\n")
                    print("We could not confirm your tag name, is it named weird?\n")
                    print(E)
            else:
                # File is meant to be by IP.  Agents are IP due to an API bug.
                if ip_update == 1:
                    try:
                        payload = {"category_name": str(c), "value": str(v), "description": str(d), "filters": {"asset": {"and": [{"field": "ipv4", "operator": "eq", "value": str(ip_list[1:])}]}}}
                        data = request_data('POST', '/tags/values', payload=payload)
                        try:
                            value_uuid = data["uuid"]
                            cat_uuid = data['category_uuid']
                            print("\nI've created your new Tag - {} : {}\n".format(c, v))
                            print("The Category UUID is : {}\n".format(cat_uuid))
                            print("The Value UUID is : {}\n".format(value_uuid))
                            print(str(len(tag_list)) + " IPs added to the Tag")
                        except Exception as E:
                            print("Duplicate Tag Category: You may need to delete your tag first\n")
                            print("We could not confirm your tag name, is it named weird?\n")
                            print(E)
                    except:
                        print("Duplicate Category")
                else:
                    try:
                        # Create the Tag
                        payload = {"category_name": str(c), "value": str(v), "description": str(d)}
                        data = request_data('POST', '/tags/values', payload=payload)
                        value_uuid = data["uuid"]
                        cat_uuid = data['category_uuid']
                        print("\nI've created your new Tag - {} : {}\n".format(c, v))
                        print("The Category UUID is : {}\n".format(cat_uuid))
                        print("The Value UUID is : {}\n".format(value_uuid))
                        update_tag(c, v, tag_list)
                        print(str(len(tag_list)) + " UUIDs added to the Tag")
                    except Exception as E:
                        print("Duplicate Tag Category: You may need to delete your tag first\n")
                        print("We could not confirm your tag name, is it named weird?\n")
                        print(E)
