from .database import db_query
import click
import csv
import textwrap


@click.command(help="Pull out CVE data into a nice CSV")
@click.argument('uuid')
def compare(uuid):
    data = db_query("select plugin_id, plugin_name, cvss_base_score, cvss3_base_score,  cves, severity, score, "
                    "first_found, last_found from vulns where asset_uuid='{}' and cves !=' ';".format(uuid))

    with open('cve_dump_{}.csv'.format(uuid), mode='w', encoding='utf-8', newline="") as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        header_list = ["Plugin ID", "Plugin Name", "CVE", "CVSS", "CVSS3", "VPR Score", "Severity", "First Found",
                       "Last_Found", "Instances"]

        agent_writer.writerow(header_list)

        master_list = []
        click.echo("\n{:10} {:75} {:16} {:6} {:6} {:6} {:10} {}".format("Plugin ID", "Plugin Name", "CVE", "CVSS", "CVSS3", "VPR", "Severity", "instances"))
        click.echo("-" * 150)
        for plugin in data:
            plugin_id = plugin[0]
            plugin_name = str(plugin[1])
            cvss = str(plugin[2])
            cvss3 = str(plugin[3])

            try:
                cve_list = eval(plugin[4])
            except SyntaxError:
                cve_list = ["NO-CVE"]

            severity = plugin[5]
            vpr = str(plugin[6])
            first_found = str(plugin[7])
            last_found = str(plugin[8])

            for cve in cve_list:

                if cve not in master_list:
                    # Count total instances
                    instances = db_query("select count(*) from vulns where cves LIKE '%" + cve + "%';")

                    master_list.append(cve)
                    click.echo("{:10} {:75} {:16} {:6} {:6} {:6} {:10} {}".format(plugin_id, textwrap.shorten(plugin_name, width=65), cve, cvss, cvss3, vpr, severity, instances[0][0]))

                    csv_update_list = [plugin_id, plugin_name, cve, cvss, cvss3, vpr, severity, first_found, last_found, instances[0][0]]
                    agent_writer.writerow(csv_update_list)

    click.echo("\nYou're export: cve_dump_{}.csv is finished\n".format(uuid))
