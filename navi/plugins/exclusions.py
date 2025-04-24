import click
import pprint
from .api_wrapper import tenb_connection
from .database import db_query
import datetime

tio = tenb_connection()


@click.command(help="Create or delete exclusions")
@click.option('--name', default=None, required=True, help="The name of your exclusion")
@click.option('--members', default=None, help="The members of your exclusion, IPs or subnets")
@click.option('--start', default=None, required=True, help="The start time of the exclusion - YYYY-MM-DD HH:MM")
@click.option('--end', default=None, required=True, help="The endtime of the exclusion - YYYY-MM-DD HH:MM")
@click.option('--freq', multiple=False, required=True, default=["DAILY"],
              type=click.Choice(["ONETIME", "DAILY", "WEEKLY", "MONTHLY", "YEARLY"]),
              help='The frequency of the exclusion')
@click.option('--day', required=True, default="")
@click.option('--c', default=None, help='Category of the Tag you want to exclude')
@click.option('--v', default=None, help='Value of the Tag you want to exclude')
def exclude(name, members, start, end, freq, day, c, v):
    if c:
        if v is None:
            click.echo("You must enter a Value if you are going to Exclude by tag.")
        if v:
            data = db_query("select asset_ip from tags where "
                            "tag_key ='" + str(c) + "' and tag_value = '" + str(v) + "';")
            members_list = []
            for assets in data:
                members_list.append(assets[0])

            exclude_request = tio.exclusions.create(name=name,
                                                    start_time=datetime.datetime.strptime
                                                    (start, '%Y-%m-%d %H:%M'),
                                                    end_time=datetime.datetime.strptime
                                                    (end, '%Y-%m-%d %H:%M'),
                                                    frequency=freq,
                                                    members=members_list,
                                                    day_of_month=day,
                                                    description="Created using Navi; IPs by Tag: {}:{}".format(c, v))

            pprint.pprint(exclude_request)
    else:
        if members is None:
            click.echo("\nYou need to specify a Tag or a IP/subnet to exclude\n")
            exit()
        else:
            exclude_request = tio.exclusions.create(name=name,
                                                    start_time=datetime.datetime.strptime
                                                    (start, '%Y-%m-%d %H:%M')
                                                    , end_time=datetime.datetime.strptime
                                                    (end, '%Y-%m-%d %H:%M'),
                                                    frequency=freq, members=list(members.split(",")),
                                                    day_of_month=day,
                                                    description="Created using Navi: manually entered via the CLI")
            click.echo(exclude_request)
