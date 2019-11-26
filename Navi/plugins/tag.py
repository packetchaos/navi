import click
from .database import new_db_connection
from .api_wrapper import request_data
from .tag_helper import update_tag
from sqlite3 import Error

@click.command(help="Create a Tag Category/Value Pair")
@click.option('--c', default='', help="Create a Tag with the following Category name")
@click.option('--v', default='', help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by Navi', help="Description for your Tag")
@click.option('--plugin', default='', help="Create a tag by plugin ID")
@click.option('--name', default='', help="Create a Tag by the text found in the Plugin Name")
@click.option('--group', default='', help="Create a Tag based on a Agent Group")
def tag(c, v, d, plugin, name, group):

    if c == '':
        print("Category is required.  Please use the --c command")

    if v == '':
        print("Value is required. Please use the --v command")

    if plugin:
        try:
            tag_list = []
            ip_list = ""
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_id=%s;" % (plugin))

                plugin_data = cur.fetchall()
                for x in plugin_data:

                    ip = x[0]
                    id = x[1]

                    #ensure the ip isn't already in the list
                    if ip not in tag_list:
                        tag_list.append(id)
                        ip_list = ip_list + "," + ip
                else:
                    pass
            if ip_list == '':
                print("\nYour tag resulted in 0 Assets, therefore the tag wasn't created\n")
            else:
                payload = {"category_name":str(c), "value":str(v), "description":str(d), "filters":{"asset":{"and":[{"field":"ipv4","operator":"eq","value":str(ip_list[1:])}]}}}
                data, stat = request_data('POST', '/tags/values', payload=payload)
                print(ip_list)

                if stat == 400:
                    print("Your Tag has not be created; Update functionality hasn't been added yet")
                    print(data['error'])
                    #try to update the tag
                    update_tag(c,v,tag_list)
                else:
                    #pprint.pprint(data)
                    print("\nI've created your new Tag - {} : {}\n".format(c,v))
                    print("The Category UUID is : {}\n".format(data['category_uuid']))
                    print("The Value UUID is : {}\n".format(data['uuid']))
                    print("The following IPs were added to the Tag:")
                    print(ip_list[1:])

        except Error as e:
            print(e)

    if name != '':
        try:
            tag_list = []
            ip_list = ""
            database = r"navi.db"
            conn = new_db_connection(database)
            with conn:
                cur = conn.cursor()
                cur.execute("SELECT asset_ip, asset_uuid, output from vulns where plugin_name LIKE '%"+name+"%';")

                plugin_data = cur.fetchall()
                for x in plugin_data:

                    ip = x[0]
                    id = x[1]
                    if ip not in tag_list:
                        tag_list.append(id)
                        ip_list = ip_list + "," + ip
                    else:
                        pass
                if ip_list == '':
                    print("\nYour tag resulted in 0 Assets, therefore the tag wasn't created\n")
                else:
                    payload = {"category_name":str(c), "value":str(v), "description":str(d), "filters":{"asset":{"and":[{"field":"ipv4","operator":"eq","value":str(ip_list[1:])}]}}}
                    data, stat = request_data('POST', '/tags/values', payload=payload)

                    if stat == 400:
                        print("Your Tag has not be created; Update functionality hasn't been added yet")
                        print(data['error'])
                        #try to update the tag
                        update_tag(c,v,tag_list)
                    else:

                        print("\nI've created your new Tag - {} : {}\n".format(c,v))
                        print("The Category UUID is : {}\n".format(data['category_uuid']))
                        print("The Value UUID is : {}\n".format(data['uuid']))
                        print("The following IPs were added to the Tag:\n")
                        print(ip_list[1:])

        except Error as e:
            print(e)

    if group != '':
        try:
            group_data = request_data('GET', '/scanners/1/agent-groups')
            for agent_group in group_data['groups']:
                group_name = agent_group['name']
                group_id = agent_group['id']

                if group_name == group:
                    data = request_data('GET', '/scanners/1/agent-groups/'+str(group_id)+'/agents')
                    ip_list = ''

                    for agent in data['agents']:
                        ip_address = agent['ip']
                        ip_list = ip_list + "," + ip_address

                    payload = {"category_name":str(c), "value":str(group), "description":str(d), "filters":{"asset":{"and":[{"field":"ipv4","operator":"eq","value":str(ip_list[1:])}]}}}
                    data2, stat = request_data('POST', '/tags/values', payload=payload)
                    if stat == 400:
                        print("Your Tag has not be created; Update functionality hasn't been added yet\n")
                        print("Delete the current tag to update it.\n")
                        print(data2['error'])

                    else:
                        print("\nI've created your new Tag - {} : {}\n".format(c,v))
                        print("The Category UUID is : {}\n".format(data2['category_uuid']))
                        print("The Value UUID is : {}\n".format(data2['uuid']))
                        print("The following IPs were added to the Tag:")
                        print(ip_list[1:])


        except:
            print("You might not have agent groups, or you are using Nessus Manager.  ")
