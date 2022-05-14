import click
from .database import new_db_connection, create_table, drop_tables, db_query


def reset_sla():
    click.echo("\nYou don't have any SLA data.  Enter your SLA now. \n")
    critical = input("Enter the SLA in days for Critical CVE3 Vulns: ")
    high = input("Enter the SLA in days for High CVE3 Vulns: ")
    medium = input("Enter the SLA in days for Medium CVE3 Vulns: ")
    low = input("Enter the SLA in days for Low CVE3 Vulns: ")

    database = r"navi.db"
    conn = new_db_connection(database)
    drop_tables(conn, 'sla')

    create_sla_table = """CREATE TABLE IF NOT EXISTS sla (
                                critical text,
                                high text,
                                medium text, 
                                low text 
                                );"""
    create_table(conn, create_sla_table)

    sla_info = (critical, high, medium, low)
    with conn:
        sql = '''INSERT or IGNORE into sla(critical, high, medium, low) VALUES(?,?,?,?)'''
        cur = conn.cursor()
        cur.execute(sql, sla_info)


@click.command(help="Enter or Overwrite your SLA information")
@click.option("-reset", is_flag=True, help="reset your SLA")
def sla(reset):
    if reset:
        click.echo("\nFor now, SLAs are calculated on export.  So rerun 'navi update fixed' to get accurate SLA results\n")
        reset_sla()
    try:
        sla_data = db_query("select * from sla;")
        click.echo("\nHere is your Current SLA data")
        critical, high, medium, low = sla_data[0]

        click.echo("\n     Critical SLA: {}".format(critical))
        click.echo("     High SLA: {}".format(high))
        click.echo("     Medium SLA: {}".format(medium))
        click.echo("     Low SLA: {}\n".format(low))
    except:
        reset_sla()
