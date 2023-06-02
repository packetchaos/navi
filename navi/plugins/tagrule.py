from .api_wrapper import tenb_connection
import click

tio = tenb_connection()


@click.command(help="Create Tag rules in Tenable.io")
@click.option('--c', default='', help="Create a Tag with the following Category name")
@click.option('--v', default='', help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by navi', help="Description for your Tag")
@click.option('--filter', default='', help="Filter used to tag assets")
@click.option('--action', default='', help="Type of operator")
@click.option('--value', default='', help="Filter value")
def tagrule(c, v, filter, action, value, d):
    rule_tuple = (filter, action, [value])
    tio.tags.create(c, v, filters=[rule_tuple], description=d)
