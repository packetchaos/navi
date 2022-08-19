import click
from .fixed_export import calculate_sla, reset_sla, print_sla


@click.group(help="Set, Reset and Calculate SLAs")
def sla():
    pass


@sla.command(help="Overwrite your SLA information")
@click.option("--critical", default='', help="Set your Critical Vulnerability SLA")
@click.option("--high", default='', help="Set your High Vulnerability SLA")
@click.option("--medium", default='', help="Set your Meduim SLA")
@click.option("--low", default='', help="Set your Low SLA")
def reset(critical, high, medium, low):

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


@sla.command(help="Calculate SLA times")
def calculate():
    try:
        calculate_sla("total")
        calculate_sla("critical")
        calculate_sla("high")
        calculate_sla("medium")
        calculate_sla("low")
        click.echo()
    except:
        click.echo("\n You need to run `navi update fixed` first\n")
