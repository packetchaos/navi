from .database import db_query
import click
import csv


@click.command(help="Pull out CVE data into a nice CSV")
@click.argument('uuid')
def compare(uuid):
    data = db_query("select plugin_id, plugin_name, cves, severity, score from vulns where asset_uuid='{}' and cves !=' ';".format(uuid))

    with open('cve_dump_{}.csv'.format(uuid), mode='w') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["Plugin ID", "Plugin Name", "CVE", "VPR Score", "Severity"]

        agent_writer.writerow(header_list)

        master_list = []
        for plugin in data:
            plugin_id = plugin[0]
            plugin_name = str(plugin[1])
            try:
                cve_list = eval(plugin[2])
            except SyntaxError:
                cve_list = ["NO-CVE"]

            severity = plugin[3]
            score = plugin[4]

            for cve in cve_list:

                if cve not in master_list:
                    master_list.append(cve)
                    print("{} : {} : {}".format(plugin_id, plugin_name, cve))

                    csv_update_list = [plugin_id, plugin_name, cve, score, severity]
                    agent_writer.writerow(csv_update_list)
