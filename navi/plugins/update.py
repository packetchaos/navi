import click
from .th_asset_export import asset_export
from .th_vuln_export import vuln_export
from .was_data_export import grab_scans
from .th_compliance_export import compliance_export


def threads_check(threads):
    if threads != 10:  # Limit the amount of threads to avoid issues
        click.echo("\nUsing {} thread(s) at your request".format(threads))
        if threads not in range(1, 11):
            click.echo("Enter a value between 1 and 10")
            exit()


@click.group(help="Update the local Navi repository - saved in your current dir")
def update():
    pass


@update.command(help="Perform a full update (30d Vulns / 90d Assets); Delete the current Database")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def full(threads):

    if threads:
        threads_check(threads)

    exid = '0'

    vuln_export(30, exid, threads)
    asset_export(90, exid, threads)


@update.command(help="Update the Asset Table")
@click.option('--days', default='90', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def assets(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    asset_export(days, exid, threads)


@update.command(help="Update the vulns Table")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def vulns(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    vuln_export(days, exid, threads)


@update.command(help="Update the Was Data")
def was():
    grab_scans()


@update.command(help="Update the Compliance data")
@click.option('--days', default='30', help="Limit the download to X # of days")
@click.option('--exid', default='0', help="Download using a specified Export ID")
@click.option('--threads', default=10, help="Control the threads to speed up or slow down downloads - (1-10)")
def compliance(threads, days, exid):
    if threads:
        threads_check(threads)

    if exid == ' ':
        exid = '0'

    compliance_export(days, exid, threads)
