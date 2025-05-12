import csv
import click
from sqlite3 import Error
from .api_wrapper import request_data


def add_helper(file, source):
    asset_lists = []
    try:
        with open(file, 'r', newline='') as new_file:
            add_assets = csv.reader(new_file)
            for row in add_assets:
                asset = {}
                ipv4 = []
                macs = []
                fqdns = []
                hostnames = []

                ipv4.append((row[0]))
                asset["ip_address"] = ipv4

                macs.append(row[1])
                asset["mac_address"] = macs

                fqdns.append(row[2])
                asset["fqdn"] = fqdns

                hostnames.append(row[3])
                asset["hostname"] = hostnames

                asset_lists.append(asset)
    except Error as e:
        click.echo(e)
    except TypeError as f:
        click.echo("\nCheck your permissions or your API keys\n")
        click.echo(f)
    except IndexError:
        click.echo("\nPlease ensure you have all four columns. IP, MAC, FQDN, HOSTNAME\n"
                   "Missing a column will produce this error\n\n")
        exit()

    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    if len(asset_lists) > 1999:
        # break the list into 2000 IP chunks
        for chunks in chunks(asset_lists, 1999):

            payload = {"assets": chunks, "source": source}
            click.echo("\nYour list has more than 2000 hosts in it; I'm breaking them into groups of 1999.\n")
            click.echo("Adding:{} Assets with source {}\n".format(len(chunks), source))

            data = request_data('POST', '/import/assets', payload=payload)
            click.echo("Your Import ID is : {}".format(data['asset_import_job_uuid']))

    else:
        payload = {"assets": asset_lists, "source": source}

        click.echo("Adding:{} Assets\n".format(len(asset_lists)))

        data = request_data('POST', '/import/assets', payload=payload)
        click.echo("Your Import ID is : {}".format(data['asset_import_job_uuid']))
