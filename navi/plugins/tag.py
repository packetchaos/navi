import click
import csv
from .database import new_db_connection, db_query
from .api_wrapper import request_data, tenb_connection
from .tag_helper import update_tag, confirm_tag_exists, grab_all_tags, remove_tag
from sqlite3 import Error
import pprint
from datetime import datetime


def tag_by_tag(c, v, d, cv, cc, match):
    # BUG: Does not check to see if rule exists right now.

    tag_uuid = 0
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


                                #rules_list.append({"field": "tag.{}".format(str(cc)), "operator": "set-has", "value": str(cv)})
                                #print("New rules {} \n".format(rules_list))


                payload = {"category_name": str(c), "value": str(v), "description": str(d), "filters": {"asset": {str(match): rules_list}}}
                # Update the Parent Tag with the new child tag information
                print(payload)
                #data = request_data('PUT', '/tags/values/' + tag_uuid, payload=payload)

                #value_uuid = data["uuid"]
                #cat_uuid = data['category_uuid']
                #click.echo("\nI've Updated your Tag - {} : {}\n".format(c, v))
                #click.echo("The Category UUID is : {}\n".format(cat_uuid))
                #click.echo("The Value UUID is : {}\n".format(value_uuid))
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
                payload = {"category_name": str(c), "value": str(v), "description": str(d), "filters":
                           {"asset": {str(match): [{"field": "tag.{}".format(cc), "operator": "set-has", "value": str(cv)}]}}}
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
    # Generator to split IPs into 2000 IP chunks
    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    # We Want to bail if the result is 0 Assets
    if not tag_list:
        click.echo("\nYour tag {}:{} resulted in 0 Assets, therefore the tag wasn't created\n".format(c,v))
        exit()
    elif tag_list == 'manual':
        # Create a blank Tag
        payload = {"category_name": str(c), "value": str(v), "description": str(d)}
        data = request_data('POST', '/tags/values', payload=payload)
        value_uuid = data["uuid"]
        cat_uuid = data['category_uuid']
        click.echo("\nI've created your new Tag - {} : {}\n".format(c, v))
        click.echo("The Category UUID is : {}\n".format(cat_uuid))
        click.echo("The Value UUID is : {}\n".format(value_uuid))
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
    tio = tenb_connection()

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


@click.command(help="Create a Tag Category/Value Pair")
@click.option('--c', default='', help="Create a Tag with the following Category name")
@click.option('--v', default='', help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by navi', help="Description for your Tag")
@click.option('--plugin', default='', help="Create a tag by plugin ID")
@click.option('--name', default='', help="Create a Tag by the text found in the Plugin Name")
@click.option('--group', default='', help="Create a Tag based on a Agent Group")
@click.option('--output', default='', help="Create a Tag based on the text in the output. Requires --plugin")
@click.option('--port', default='', help="Create a Tag based on Assets that have a port open.")
@click.option('--file', default='', help="Create a Tag based on IPs in a CSV file.")
@click.option('--scantime', default='', help="Create a Tag for assets that took longer than supplied minutes")
@click.option('--cc', default='', help="Add a Tag to a new parent tag: Child Category")
@click.option('--cv', default='', help="Add a Tag to a new parent tag: Child Value")
@click.option('--scanid', default='', help="Create a tag by Scan ID")
@click.option('--histid', default=None, help="Focus on a specific scan history; Requires --scanid")
@click.option('-all', is_flag=True, help="Change Default Match rule of 'or' to 'and'")
@click.option('--query', default='', help="Use a custom query to create a tag.")
@click.option('-remove', is_flag=True, help="Remove this tag from all assets to support ephemeral asset tagging")
@click.option('--cve', default='', help="Tag based on a CVE ID")
@click.option('--xrefs', default='', help="Tag by Cross References like CISA")
@click.option('--xid', '--xref-id', default='', help="Specify a Cross Reference ID")
@click.option('--manual', default='', help="Tag assets manually by supplying the UUID")
@click.option('--missed', default='', help="Tag Agents that missed authentication in given number of days")
@click.option('--byadgroup', default='', help="Create Tags based on AD groups in a CSV")
def tag(c, v, d, plugin, name, group, output, port, scantime, file, cc, cv, scanid, all, query, remove, cve, xrefs, xid,
        manual, histid, missed, byadgroup):
    # start a blank list
    tag_list = []
    ip_list = ""

    if c == '':
        click.echo("Category is required.  Please use the --c command")
        exit()

    if v == '':
        click.echo("Value is required. Please use the --v command")
        exit()

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
            if output != "":
                plugin_data = db_query("SELECT asset_ip, asset_uuid, fqdn, network from vulns LEFT JOIN assets ON "
                                       "asset_uuid = uuid "
                                       "where plugin_id='" + plugin + "' and output LIKE '%" + output + "%';")
            else:
                plugin_data = db_query("SELECT asset_ip, asset_uuid, output from vulns where plugin_id={};".format(plugin))

            for x in plugin_data:
                uuid = x[1]
                # To reduce duplicates check for the UUID in the list.
                if uuid not in tag_list:
                    tag_list.append(uuid)
                else:
                    pass
        except Error:
            pass

        tag_by_uuid(tag_list, c, v, d)

    if port != '':
        d = d + "\nTag by Port: {}".format(port)
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT asset_uuid from vulns where port=" + port + " and "
                                                                            "(plugin_id='11219' "
                                                                            "or plugin_id='14272' "
                                                                            "or plugin_id='14274' "
                                                                            "or plugin_id='34220' "
                                                                            "or plugin_id='10335');")

            data = cur.fetchall()

            try:
                for vulns in data:
                    uuid = vulns[0]
                    # To reduce duplicates check for the UUID in the list.
                    if uuid not in tag_list:
                        tag_list.append(uuid)
            except ValueError:
                pass
        tag_by_uuid(tag_list, c, v, d)

    if name != '':
        d = d + "\nTag by Plugin Name: {}".format(name)
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

        tag_by_uuid(tag_list, c, v, d)

    if group != '':
        d = d + "\nTag by Agent Group: {}".format(group)
        from uuid import UUID

        try:
            offset = 0
            total = 0
            limit = 5000
            while offset <= total:
                querystring = {"limit": limit, "offset": offset}
                group_data = request_data('GET', '/scanners/1/agent-groups', params=querystring)

                for agent_group in group_data['groups']:
                    group_name = agent_group['name']
                    group_id = agent_group['id']

                    # Match on Given Name
                    if group_name == group:
                        agent_data = request_data('GET', '/scanners/1/agent-groups/'
                                                  + str(group_id) + '/agents', params=querystring)
                        total = agent_data['pagination']['total']

                        for agent in agent_data['agents']:
                            new_uuid = UUID(agent['uuid']).hex
                            tag_uuid = db_query("select uuid from assets where agent_uuid='{}'".format(new_uuid))
                            # New agents will not have a corresponding UUID and will throw an error.
                            # Since they can not be tagged without a UUID, we will silently skip over the agent
                            try:
                                tag_list.append(tag_uuid[0][0])
                            except IndexError:
                                pass
                offset += 5000
                limit += 5000
        except Error:
            click.echo("You might not have agent groups, or you are using Nessus Manager.  ")

        tag_by_uuid(tag_list, c, v, d)

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

                        except:
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

        tag_by_uuid(tag_list, c, v, d)

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

        tag_by_uuid(uuid_list, c, v, d)

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
                    new_scan_data = None
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
        if ("uuid" or "asset_uuid") in str(query):

            data = db_query(query)

            for asset in set(data):
                tag_list.append(asset[0])

            tag_by_uuid(tag_list, c, v, d)

        else:
            click.echo("\nYou have to return uuids or asset_uuid. \nYour query must have uuid or asset_uuid\n")
            exit()

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
                if uuid not in tag_list:
                    tag_list.append(uuid)

                else:
                    pass
            tag_by_uuid(tag_list, c, v, d)

    if xrefs:
        d = d + "\nTag by Cross Reference: {}".format(xrefs)
        if xid:
            d = d + "\n Refined tag search to the follow Cross Reference ID text search: {}".format(xid)
            xref_data = db_query("select asset_uuid from vulns where "
                                 "xrefs LIKE '%{}%' AND xrefs LIKE '%{}%'".format(xrefs, xid))

        else:
            xref_data = db_query("select asset_uuid from vulns where xrefs LIKE '%{}%'".format(xrefs))

        for x in xref_data:
            uuid = x[0]
            if uuid not in tag_list:
                tag_list.append(uuid)

            else:
                pass
        tag_by_uuid(tag_list, c, v, d)

    if manual:
        tag_by_uuid(manual, c, v, d)

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
        except:
            click.echo("\nMake sure you are submitting an Integer\n")

        tag_by_uuid(tag_list, c, v, d)

    if byadgroup:

        filename = byadgroup #'HFAUsersWithDevices.csv'

        hfa_dict = {}
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
                except:
                    pass
        # Create the dictionary
        hfa_dict = {"{}".format(dname[:-1]): new_list}

        #Gab hostnames and UUIDs
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
                #print(v)
                #print(data)
                for x in clean_hostname_list:
                    #print(x[0])
                    if v in x[0]:
                        print("tag --c AD Groups --v {}".format(key))
                        tag_list.append(x[1])
            tag_by_uuid(tag_list, c="AD Groups", v=key, d="AD Groups tagged by navi")
            #print(tag_list)