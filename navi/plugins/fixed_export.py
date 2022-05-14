import click
from .api_wrapper import tenb_connection
from .database import new_db_connection, insert_fixed, db_query, drop_tables
from .dbconfig import create_fixed_table
import datetime
import arrow

tio = tenb_connection()


def sla_compare(severity, seconds):
    sla_data = db_query("select * from sla;")

    critical, high, medium, low = sla_data[0]

    if severity == "critical":
        if seconds > int(critical) * 86400:
            return "Fail"
        else:
            return "Pass"

    elif severity == "high":

        if seconds > int(high) * 86400:
            return "Fail"
        else:
            return "Pass"

    elif severity == "medium":

        if seconds > int(medium) * 86400:
            return "Fail"
        else:
            return "Pass"

    elif severity == "low":

        if seconds > int(low) * 86400:
            return "Fail"
        else:
            return "Pass"

    else:
        pass


def compare_and_return_delta(last_fixed, first_found):
    # Turns Last_fixed and First found into Unix timestamps and returns the delta
    new_time = datetime.datetime.timestamp(datetime.datetime.strptime(last_fixed, '%Y-%m-%dT%H:%M:%S.%f%z')) - datetime.datetime.timestamp(datetime.datetime.strptime(first_found, '%Y-%m-%dT%H:%M:%S.%f%z'))

    return new_time


def calculate_sla(severity):

    if severity == 'total':
        total = db_query("select count(plugin_id) from fixed where severity !='info';")[0][0]
        pass_total = db_query("select count(plugin_id) from fixed where state=='FIXED' and pass_fail =='Pass';")[0][0]
        fixed_total = db_query("select count(plugin_id) from fixed where state=='FIXED';")[0][0]

        print("\nTotal Vulns found: {}".format(total))
        print("Total vulns fixed in this period: {}".format(fixed_total))
        try:
            print("Total Fixed rate: {:.0%}\n".format((fixed_total/total)))
        except ZeroDivisionError:
            print("Total Fixed rate: 0%")

        print("Total vulns fixed within SLA: {}".format(pass_total))
        try:
            print("{:.0%} Success Rate".format((pass_total/total)))
        except ZeroDivisionError:
            print("0% Success Rate")

    else:
        severity_total = db_query("select count(plugin_id) from fixed where severity =='{}';".format(severity))[0][0]
        sevrity_pass_total = db_query("select count(plugin_id) from fixed where severity =='{}' and pass_fail =='Pass';".format(severity))[0][0]

        print("\nTotal {} Vulns found this period: {}".format(severity, severity_total ))
        print("Total {} vulns fixed within SLA: {}".format(severity, sevrity_pass_total))
        try:
            print("{:.0%} Success Rate".format((sevrity_pass_total/severity_total)))
        except ZeroDivisionError:
            print("0% Success Rate")


def fixed_export(category, value, days):
    database = r"navi.db"
    fixed_conn = new_db_connection(database)

    drop_tables(fixed_conn, "fixed")

    create_fixed_table()

    click.echo("\n***Navi calculates SLAs on export request.  So re-run 'navi update fixed' after changing your SLA***\n")
    click.echo("Downloading all of your Fixed, Open and Reopened vulns into a new Table called 'fixed'\n")
    with fixed_conn:
        if category and value:
            tags = (category, value)

            for vulns in tio.exports.vulns(state=['fixed', 'open', 'reopened'], tags=[tags], since=int(arrow.now().shift(days=-int(days)).timestamp())):

                asset_uuid = vulns['asset']['uuid']
                port = vulns['port']['port']
                plugin_id = vulns['plugin']['id']
                plugin_name = vulns['plugin']['name']

                first_found = vulns['first_found']

                try:
                    last_fixed = vulns['last_fixed']
                except KeyError:
                    last_fixed = None

                last_found = vulns['last_found']

                try:
                    output = vulns['output']
                except KeyError:
                    output = None

                severity = vulns['severity']

                if last_fixed is not None:
                    try:
                        delta = compare_and_return_delta(last_fixed, first_found)

                        pass_fail = sla_compare(severity, delta)
                    except ValueError:
                        #print(plugin_id, last_fixed, first_found, asset_uuid)
                        delta = None
                        pass_fail = None
                else:
                    delta = None
                    pass_fail = None

                state = vulns['state']

                special_url = "https://cloud.tenable.com/tio/app.html#/vulnerability-management/dashboard/assets/asset-details/{}/vulns/vulnerability-details/{}/details".format(asset_uuid, plugin_id)

                data_list = [asset_uuid, output, plugin_id, plugin_name, port, first_found, last_fixed, last_found, severity, delta, pass_fail, state, special_url]

                insert_fixed(fixed_conn, data_list)

        else:

            for vulns in tio.exports.vulns(state=['fixed', 'open', 'reopened'], since=int(arrow.now().shift(days=-int(days)).timestamp())):

                asset_uuid = vulns['asset']['uuid']
                port = vulns['port']['port']
                plugin_id = vulns['plugin']['id']
                plugin_name = vulns['plugin']['name']

                first_found = vulns['first_found']

                try:
                    last_fixed = vulns['last_fixed']
                except KeyError:
                    last_fixed = None

                last_found = vulns['last_found']

                try:
                    output = vulns['output']
                except KeyError:
                    output = None

                severity = vulns['severity']

                if last_fixed is not None:
                    try:
                        delta = compare_and_return_delta(last_fixed, first_found)

                        pass_fail = sla_compare(severity, delta)
                    except ValueError:
                        #print(plugin_id, last_fixed, first_found, asset_uuid)
                        delta = None
                        pass_fail = None
                else:
                    delta = None
                    pass_fail = None

                state = vulns['state']

                special_url = "https://cloud.tenable.com/tio/app.html#/vulnerability-management/dashboard/assets/asset-details/{}/vulns/vulnerability-details/{}/details".format(asset_uuid, plugin_id)

                data_list = [asset_uuid, output, plugin_id, plugin_name, port, first_found, last_fixed, last_found, severity, delta, pass_fail, state, special_url]

                insert_fixed(fixed_conn, data_list)
