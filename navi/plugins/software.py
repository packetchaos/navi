import pprint

import click
from .dbconfig import create_software_table, new_db_connection
from .database import db_query, insert_software, drop_tables
import textwrap


@click.group(help="Generate a report of software in your environment")
def software():
    pass


def parse_22869(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='22869'")
    for data in software_data:
        asset_uuid = data[1]
        for pkg in str(data[0]).splitlines():
            pkg_name = str(pkg.split("|"))
            if "packages installed" not in pkg_name:
                string_list = str(eval(pkg_name)[0]).split()
                try:
                    if len(string_list[0]) == 2:
                        new_name = "{}-{}".format(string_list[1], string_list[2])
                        if pkg_name not in soft_dict:
                            soft_dict[new_name] = [asset_uuid]
                        else:
                            soft_dict[new_name].append(asset_uuid)
                except:
                    pass


def parse_20811(soft_dict):
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='20811'")
    for data in software_data:
        asset_uuid = data[1]
        for pkg in data:
            new_string = str(pkg).splitlines()
            list = eval(str(new_string))
            for item in list:
                if "The following software" not in item:
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
            new_list = eval(str(pkg_string))
            for item in new_list[:-1]:
                if "  Location" not in item:
                    if "Error" not in item:
                        if item not in soft_dict:
                            soft_dict[item] = [host[-1]]
                        else:
                            soft_dict[item].append(host[-1])


def display_stats():
    total = db_query("select count(software_string) from software;")[0][0]
    asset_total = db_query("select count(distinct asset_uuid) from vulns;")[0][0]
    assets_with_data = db_query("select count(distinct asset_uuid) from vulns "
                                "where plugin_id ='22869' or plugin_id ='20811';")[0][0]
    assets_without_data = db_query("select hostname, uuid, ip_address from assets where  ip_address !=' ' and "
                                   "uuid not in (select asset_uuid from vulns "
                                   "where plugin_id ='22869' or plugin_id ='20811')")

    click.echo("\nUnique Software total is: " + str(total))
    click.echo("\nAssets evaluated: " + str(asset_total))
    click.echo("\nAssets with Software: " + str(assets_with_data))
    click.echo("\nAssets Without Software Plugins: " + str(len(assets_without_data)))
    click.echo()


@software.command(help="Display stats on Software")
@click.option('-missing', is_flag=True, help="Display assets missing software enumeration")
@click.option('-stats', is_flag=True, help="Display General Stats")
@click.option('--greaterthan', default=None,
              help="Display Software installed Greater than or equal to the number entered")
@click.option('--lessthan', default=None,
              help="Display Software installed less than or equal to the number entered")
def display(missing, stats, greaterthan, lessthan):

    if missing:
        click.echo("\nThese Assets do not have plugin 22869 nor 20811\n")
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

    if greaterthan:
        try:
            click.echo()
            click.echo("*"*50)
            click.echo("Below is the Software found {} times or more".format(greaterthan))
            click.echo("*" * 50)
            all_data = db_query("select * from software;")
            click.echo("{:125} {}".format("\nSoftware Package Name", "Install Count"))
            click.echo('-' * 150)
            for wares in all_data:
                length = len(eval(wares[0]))
                if int(length) >= int(greaterthan):
                    click.echo("{:125} {}".format(wares[1], len(eval(wares[0]))))
        except:
            click.echo("\nRun navi sofware Generate\n Or check your input\n")
        click.echo()

    if lessthan:
        try:
            click.echo("*" * 50)
            click.echo("Below is the Software found {} times or less".format(greaterthan))
            click.echo("*" * 50)
            all_data = db_query("select * from software;")
            click.echo("{:125} {}".format("\nSoftware Package Name", "Install Count"))
            click.echo('-' * 150)
            for wares in all_data:
                length = len(eval(wares[0]))
                if int(length) <= int(lessthan):
                    click.echo("{:125} {}".format(wares[1], len(eval(wares[0]))))
        except:
            click.echo("\nRun navi sofware Generate\n Or check your input\n")
        click.echo()


@software.command(help="Create the database table and populate the software data")
def generate():
    database = r'navi.db'
    new_conn = new_db_connection(database)
    drop_tables(new_conn, "software")
    create_software_table()
    soft_dict = {}

    # Grab 22869 Data
    parse_22869(soft_dict)

    # Grab 20811 Data
    parse_20811(soft_dict)

    with new_conn:
        new_list = []
        for item in soft_dict.items():
            # Save the uuid list as a string
            new_list = [item[0], str(item[1]).strip()]
            insert_software(new_conn, new_list)

    display_stats()

