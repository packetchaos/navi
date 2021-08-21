import click
from .database import db_query
from .tag_helper import tag_checker
from .api_wrapper import request_data


@click.command(help="Adjust ACRs in Lumin by tag")
@click.option('--acr', default='', help='Set the ACR')
@click.option('--c', default=None, required=True,  help="Tag Category to use")
@click.option('--v', default=None, required=True, help="Tag Value to use")
@click.option('--note', default="navi Generated", help="Enter a Note to your ACR update")
@click.option('-business', '-b', is_flag=True, help="Add Business Critical To ACR Change Reason(s)")
@click.option('-compliance', '-c', is_flag=True, help="Add Compliance To ACR Change Reason(s)")
@click.option('-mitigation', '-m', is_flag=True, help="Add Mitigation Controls To ACR Change Reason(s)")
@click.option('-development', '-d', is_flag=True, help="Add Development To ACR Change Reason(s)")
def lumin(acr, v, c, note, business,  compliance, mitigation, development):
    choice = []

    if business:
        choice.append("Business Critical")

    if compliance:
        choice.append("In Scope For Compliance")

    if mitigation:
        choice.append("Existing Mitigation Control")

    if development:
        choice.append("Dev Only")

    if not business and not mitigation and not compliance and not development:
        choice.append("Key Drivers does not match")

    if note != 'navi Generated':
        choice.append("Other")

    if int(acr) in range(1, 11):

        data = db_query("SELECT asset_uuid from tags where tag_key='" + c + "' and tag_value='" + v + "';")

        lumin_list = []

        for asset in data:
            uuid = asset[0]

            # First make sure the asset doesn't have a NO:UPDATE tag
            check_for_no = tag_checker(uuid, "NO", "UPDATE")
            if check_for_no == 'no':
                lumin_list.append(uuid)

        for asset_uuid in lumin_list:
            note = note + " - navi"
            lumin_payload = [{"acr_score": int(acr), "reason": choice, "note": note, "asset": [{"id": asset_uuid}]}]
            request_data('POST', '/api/v2/assets/bulk-jobs/acr', payload=lumin_payload)

        if not lumin_list:
            click.echo("\nWe did not find a Tag with that Category or Value... "
                       "It's also possible the tag has not been applied to any assets or the navi DB needs to be updated\n")
            click.echo("If you think this is an error, surround your category and value in \"\"\n")
            exit()

    else:
        click.echo("\nYou can't have a score below 1 or higher than 10\n")
