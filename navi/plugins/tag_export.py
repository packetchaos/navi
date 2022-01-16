import csv
import click
from .database import db_query
from .api_wrapper import tenb_connection

tio = tenb_connection()


def tag_export(tag_list, filename, option):
    click.echo("This export can take some time.  ~300 assets per minute.")

    # Create our headers - We will Add these two our list in order
    if option == 1:
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Agent-UUID", "last Licensed Scan Date", 'Network', 'ACR', 'AES', 'AWS ID',
                       'Info', 'Low', 'Medium', 'High', 'Critical']
    else:
        header_list = ["IP Address", "Hostname", "FQDN", "UUID", "First Found", "Last Found", "Operating System",
                       "Mac Address", "Agent-UUID", "last Licensed Scan Date", 'Network', 'ACR', 'AES', 'AWS ID']

    # Crete a csv file object
    with open('{}.csv'.format(filename), mode='w', encoding='utf-8') as csv_file:
        agent_writer = csv.writer(csv_file, delimiter=',', quotechar='"')

        # write our Header information first
        agent_writer.writerow(header_list)

        for uuid in tag_list:
            export_list = []
            data = db_query("SELECT * from assets where uuid='{}';".format(uuid))

            # SQL gives us a tuple, we need to convert it to a list.
            for item in data[0]:
                export_list.append(item)

            if option == 1:
                try:
                    asset_info = tio.workbenches.asset_info(uuid)

                    for vuln in asset_info['counts']['vulnerabilities']['severities']:
                        export_list.append(vuln["count"])  # Add the vuln counts to the new list

                except ConnectionError:
                    click.echo("Check your API keys or your internet connection")

            # write to the CSV
            agent_writer.writerow(export_list)
            print("\n{}".format(export_list))
        click.echo("\nExport success! - {}.csv\n".format(filename))
