import click
from .api_wrapper import tenb_connection
import datetime

tio = tenb_connection()


@click.command(help="Create or delete exclusions")
@click.option('--name', default=None, help="The name of your exclusion")
@click.option('--members', default=None, help="The members of your exclusion, IPs or subnets")
@click.option('--start', default=None, help="The start time of the exclusion - YYYY-MM-DD HH:MM")
@click.option('--end', default=None, help="The endtime of the exclusion - YYYY-MM-DD HH:MM")
@click.option('--freq', multiple=False, default=["DAILY"],
              type=click.Choice(["ONETIME", "DAILY", "WEEKLY", "MONTHLY", "YEARLY"]),
              help='The frequency of the exclusion')
@click.option('--day')
def exclude(name, members, start, end, freq, day):
    exclude_request = tio.exclusions.create(name=name, start_time=datetime.datetime.strptime(start, '%Y-%m-%d %H:%M')
                                            , end_time=datetime.datetime.strptime(end, '%Y-%m-%d %H:%M'),
                                            frequency=freq, members=list(members.split(",")), day_of_month=day)
    click.echo(exclude_request)
