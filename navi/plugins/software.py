import click
from .dbconfig import create_software_table, new_db_connection
from .database import db_query, insert_software, drop_tables
import pprint
import textwrap


@click.group(help="Generate a report of software in your environment")
def software():
    pass


def parse_22869(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='22869'")
    count = 0
    for data in software_data:
        asset_uuid = data[1]
        for pkg in str(data[0]).splitlines():
            count = count + 1
            #print("line", pkg)
            pkg_name = str(pkg.split("|"))
            if "packages installed" not in pkg_name:
                # Some output has "ii" in it after the split
                if "  ii  " in pkg_name:
                    #print(count, eval(pkg_name)[0][5:])
                    new_name = eval(pkg_name)[0][7:]

                    if pkg_name not in soft_dict:
                        soft_dict[new_name] = [asset_uuid]
                    else:
                        soft_dict[new_name].append(asset_uuid)
                else:
                    # pull out the software package
                    new_name = eval(pkg_name)[0][2:]

                    if pkg_name not in soft_dict:
                        soft_dict[new_name] = [asset_uuid]
                    else:
                        soft_dict[new_name].append(asset_uuid)


def parse_20811(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='20811'")
    # 22869 Parser
    for data in software_data:
        asset_uuid = data[1]
        for pkg in data:
            new_string = str(pkg).splitlines()
            list = eval(str(new_string))
            for item in list:
                if "installed" in item:
                    new_item = item.split(" [installed")
                    try:
                        if new_item[0] not in soft_dict:
                            soft_dict[new_item[0]] = [asset_uuid]
                        else:
                            soft_dict[new_item[0]].append(asset_uuid)
                    except TypeError:
                        pass


def parse_83991(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='83991'")
    for host in software_data:
        for pkg in host:
            pkg_string = str(pkg).splitlines()
            list = eval(str(pkg_string))
            for item in list[:-1]:
                if "  Location" not in item:
                    if "Error" not in item:

                        if item not in soft_dict:
                            soft_dict[item] = [host[-1]]
                        else:
                            soft_dict[item].append(host[-1])


def display_stats():
    total = db_query("select count(software_string) from software;")[0][0]
    asset_total = db_query("select count(distinct asset_uuid) from vulns;")[0][0]
    assets_with_data = \
    db_query("select count(distinct asset_uuid) from vulns where plugin_id ='22869' or plugin_id ='20811';")[0][0]
    assets_without_data = db_query("select hostname, uuid, ip_address from assets where  ip_address !=' ' and "
                                   "uuid not in (select asset_uuid from vulns "
                                   "where plugin_id ='22869' or plugin_id ='20811')")

    print("\nUnique Software total is:", total)
    print("\nAssets evaluated:", asset_total)
    print("\nAssets with Software: ", assets_with_data)
    print("\nAssets Without Software Plugins: ", len(assets_without_data))


@software.command(help="Display stats on Software")
@click.option('-missing', is_flag=True, help="Display assets missing software enumeration")
@click.option('-stats', is_flag=True, help="Display General Stats")
def display(missing, stats):
    if missing:
        assets_without_data = db_query("select hostname, uuid, ip_address, acr, aes from assets where "
                                       "ip_address !=' ' and uuid not in "
                                       "(select asset_uuid from vulns "
                                       "where plugin_id ='22869' or plugin_id ='20811')")

        click.echo("\n{:16} {:80} {:6} {:6} {}".format("IP Address", "FQDN", "AES", "ACR", "UUID"))
        click.echo("-" * 150)

        for asset in assets_without_data:
            ipv4 = str(asset[2])
            fqdn = str(asset[0])
            uuid = str(asset[1])
            exposure_score = str(asset[4])
            acr = str(asset[3])

            click.echo("{:16} {:80} {:6} {:6} {}".format(ipv4, textwrap.shorten(fqdn, width=80), exposure_score, acr, uuid))
        click.echo()

    if stats:
        display_stats()


@software.command(help="Create the database table and populate the software data")
def generate():
    database = r'navi.db'
    new_conn = new_db_connection(database)
    drop_tables(new_conn, "software")
    create_software_table()
    uuid_list = []
    soft_dict = {}

    # Grab 22869 Data
    parse_22869(soft_dict)

    # Grab 20811 Data
    parse_20811(soft_dict)

    # Grab 83911 Data
    #parse_83991(soft_dict)

    with new_conn:
        new_list = []
        for item in soft_dict.items():
            #print(item[1])
            # Save the uuid list as a string
            new_list = [item[0], str(item[1])]
            insert_software(new_conn, new_list)

    #pprint.pprint(set(massive_list_of_software))
    display_stats()

