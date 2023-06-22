from .api_wrapper import tenb_connection, request_data
import click

tio = tenb_connection()


@click.command(help="Create Tag rules in Tenable.io")
@click.option('--c', default='', help="Create a Tag with the following Category name")
@click.option('--v', default='', help="Create a Tag Value; requires --c and Category Name or UUID")
@click.option('--d', default='This Tag was created/updated by navi', help="Description for your Tag")
@click.option('--filter', default='', help="Filter used to tag assets")
@click.option('--action', default='', help="Type of operator")
@click.option('--value', default='', help="Filter value")
@click.option('--multi', default='', help="A well crafted pytenable list of tuples")
@click.option('-any', is_flag=True, help="Change the default from 'and' to 'or")
def tagrule(c, v, filter, action, value, d, multi, any):
    if c == '':
        click.echo("Category is required.  Please use the --c command")
        exit()

    if v == '':
        click.echo("Value is required. Please use the --v command")
        exit()

    if multi == '' and filter == '':
        click.echo("\nYou need to select an individual 'filter' or 'multi' for multiple filters\n")
        exit()

    if multi:
        click.echo("creating a new tag with the following list {}".format(multi))
        filter_list = []
        for os in eval(multi):
            temp_dict = {"field": os[0], "operator": os[1], "value": os[2]}
            filter_list.append(temp_dict)
            # issue with tenable.io API - Or turns in to a string value seperated by a comma
            # issue with pytenable - appends " when you add * so *centos* becomes "*centos*"
        if any:
            tio.tags.create(c, v, filters=eval(multi), filter_type="or", description=d)
        else:
            tio.tags.create(c, v, filters=eval(multi), description=d)
        #payload = {"filters": {"asset": {"or": filter_list}}, "category_name": str(c), "value": str(v), "description": str(d)}
        import pprint
        #pprint.pprint(payload)
        #data = request_data('POST', '/tags/values', payload=payload)
        #print(data)

    if filter:
        if action:
            if value:
                rule_tuple = (filter, action, [value])
                tio.tags.create(c, v, filters=[rule_tuple], description=d)
            else:
                click.echo("You must have a value if you are going to use a filter")
            exit()
        else:
            click.echo("You must have an Action if you are going to use a filter")
            exit()
