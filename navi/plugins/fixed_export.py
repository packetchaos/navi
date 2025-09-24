import click
from .api_wrapper import tenb_connection
from .database import new_db_connection, insert_fixed, db_query, drop_tables, insert_sla_data
from .dbconfig import create_fixed_table
import dateutil.parser as dp
import arrow
import time


tio = tenb_connection()


def print_sla():
    try:
        sla_data = db_query("select critical, high, medium, low from sla;")
        click.echo("\nHere is your Current SLA data")

        click.echo("\n     Critical SLA: {}".format(sla_data[0][0]))
        click.echo("     High SLA: {}".format(sla_data[0][1]))
        click.echo("     Medium SLA: {}".format(sla_data[0][2]))
        click.echo("     Low SLA: {}\n".format(sla_data[0][3]))
    except IndexError:
        click.echo("\nYou don't appear to have an SLA; Defaults have been set")
        # on failure, lets set the defaults.
        critical = 7
        high = 14
        medium = 30
        low = 180
        reset_sla(critical, high, medium, low)


def reset_sla(critical, high, medium, low):
    clear_data = db_query("DELETE table sla;")
    print("\n Resetting your SLA\n{}".format(clear_data))
    sla_info = (critical, high, medium, low)
    database = r"navi.db"
    sla_conn = new_db_connection(database)
    with sla_conn:
        insert_sla_data(sla_conn, sla_info)

    return


def sla_compare(severity, seconds):
    try:
        sla_data = db_query("select critical, high, medium, low from sla;")

        critical = sla_data[0][0]
        high = sla_data[0][1]
        medium = sla_data[0][2]
        low = sla_data[0][3]
    except IndexError:
        reset_sla(critical=7, high=30, medium=90, low=180)
        critical = 7
        high = 30
        medium = 90
        low = 180

    if severity.lower() == "critical":
        if seconds > int(critical) * 86400:
            return "Fail"
        else:
            return "Pass"

    elif severity.lower() == "high":

        if seconds > int(high) * 86400:
            return "Fail"
        else:
            return "Pass"

    elif severity.lower() == "medium":

        if seconds > int(medium) * 86400:
            return "Fail"
        else:
            return "Pass"

    elif severity.lower() == "low":

        if seconds > int(low) * 86400:
            return "Fail"
        else:
            return "Pass"

    else:
        pass


def compare_and_return_delta(last_fixed, first_found):

    if last_fixed is None:
        parsed_first_found = dp.parse(first_found)
        first_found_in_seconds = parsed_first_found.timestamp()

        current_time = time.time()

        new_time = current_time - first_found_in_seconds
    else:
        parsed_first_found = dp.parse(first_found)
        first_found_in_seconds = parsed_first_found.timestamp()

        parsed_last_fixed = dp.parse(last_fixed)
        last_fixed__in_seconds = parsed_last_fixed.timestamp()

        new_time = last_fixed__in_seconds - first_found_in_seconds

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
        sevrity_pass_total = db_query("select count(plugin_id) from fixed "
                                      "where severity =='{}' and pass_fail =='Pass';".format(severity))[0][0]

        print("\nTotal {} Vulns found this period: {}".format(severity, severity_total))
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

    click.echo("\n***Navi calculates SLAs on export request.  "
               "So re-run 'navi config update fixed' after changing your SLA***\n")
    click.echo("Downloading all of your Fixed, Open and Reopened vulns into a new Table called 'fixed'\n")
    with fixed_conn:
        if category and value:
            tags = (category, value)

            for vulns in tio.exports.vulns(state=['fixed', 'open', 'reopened'], tags=[tags],
                                           since=int(arrow.now().shift(days=-int(days)).timestamp())):

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
                # Get the delta from today's date or ast fixed from the time it was first found
                delta = compare_and_return_delta(last_fixed, first_found)
                # Compare that data against the current sla
                pass_fail = sla_compare(severity, delta)

                state = vulns['state']

                special_url = ("https://cloud.tenable.com/tio/app.html#/vulnerability-management"
                               "/dashboard/assets/asset-details/{}/vulns/"
                               "vulnerability-details/{}/details").format(asset_uuid, plugin_id)

                data_list = [asset_uuid, output, plugin_id, plugin_name, port, first_found, last_fixed,
                             last_found, severity, delta, pass_fail, state, special_url]

                insert_fixed(fixed_conn, data_list)

        else:

            for vulns in tio.exports.vulns(state=['fixed', 'open', 'reopened'],
                                           since=int(arrow.now().shift(days=-int(days)).timestamp())):

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
                # Get the delta from today's date or ast fixed from the time it was first found
                delta = compare_and_return_delta(last_fixed, first_found)
                # Compare that data against the current sla
                pass_fail = sla_compare(severity, delta)

                state = vulns['state']

                special_url = ("https://cloud.tenable.com/tio/app.html#/vulnerability-management/"
                               "dashboard/assets/asset-details/{}/vulns/"
                               "vulnerability-details/{}/details").format(asset_uuid, plugin_id)

                data_list = [asset_uuid, output, plugin_id, plugin_name, port, first_found, last_fixed,
                             last_found, severity, delta, pass_fail, state, special_url]

                insert_fixed(fixed_conn, data_list)
    click.echo("Success!")
