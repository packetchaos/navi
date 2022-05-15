import click
from .database import new_db_connection, create_table, drop_tables, db_query


def reset_sla(critical, high, medium, low):
    print("\n Resetting your SLA Now\n")
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


def print_sla():
    try:
        sla_data = db_query("select * from sla;")
        click.echo("\nHere is your Current SLA data")

        critical, high, medium, low = sla_data[0]

        click.echo("\n     Critical SLA: {}".format(critical))
        click.echo("     High SLA: {}".format(high))
        click.echo("     Medium SLA: {}".format(medium))
        click.echo("     Low SLA: {}\n".format(low))
    except:
        # on failure, lets set the defaults.
        critical = 7
        high = 14
        medium = 30
        low = 180
        reset_sla(critical, high, medium, low)


@click.command(help="Enter or Overwrite your SLA information")
@click.option("-reset", is_flag=True, help="reset your SLA")
@click.option("--critical", default='', help="Set your Critical Vulnerability SLA")
@click.option("--high", default='', help="Set your High Vulnerability SLA")
@click.option("--medium", default='', help="Set your Meduim SLA")
@click.option("--low", default='', help="Set your Low SLA")
def sla(reset, critical, high, medium, low):
    if reset:

        if critical == '' and high == '' and medium == '' and low == '':
            print("You Entered Nothing, but choose to reset your SLA.  I'm using the Defaults")
            # Set Defaults: user could only select one
            reset_sla(7, 14, 30, 180)
            print_sla()
        else:
            if critical == '':
                critical = 7

            if high == '':
                high = 14

            if medium == '':
                medium = 30

            if low == '':
                low = 180

            reset_sla(critical, high, medium, low)
            print_sla()
    else:
        print_sla()
