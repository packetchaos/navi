from collections import defaultdict
import click
from .database import db_query
from .tag_helper import tag_checker
from .api_wrapper import request_data


@click.command(help="Adjust ACRs in Tenable One by tag")
@click.option('--acr', default='', help='Set the ACR')
@click.option('--mod', required=True, type=click.Choice(['set', 'inc', 'dec'], case_sensitive=True),
              multiple=False, help="Increases/Decreases or Sets the ACR value")
@click.option('--c', default=None, required=True,  help="Tag Category to use")
@click.option('--v', default=None, required=True, help="Tag Value to use")
@click.option('--note', default="navi Generated", help="Enter a Note to your ACR update")
@click.option('-business', '-b', is_flag=True, help="Add Business Critical To ACR Change Reason(s)")
@click.option('-compliance', '-c', is_flag=True, help="Add Compliance To ACR Change Reason(s)")
@click.option('-mitigation', '-m', is_flag=True, help="Add Mitigation Controls To ACR Change Reason(s)")
@click.option('-development', '-d', is_flag=True, help="Add Development To ACR Change Reason(s)")
def lumin(acr, v, c, note, business,  compliance, mitigation, development, mod):
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
        acr_dict = defaultdict(list)

        data = db_query("select acr, asset_uuid from tags left join assets on assets.uuid = tags.asset_uuid "
                        "where tag_key='{}' and tag_value='{}';".format(c, v))

        # create a list of all UUIDs associated; this will be used for comparson later
        allow_list = []
        for asset in data:
            uuid = asset[1]
            # First make sure the asset doesn't have a NO:UPDATE tag
            check_for_no = tag_checker(uuid, "NO", "UPDATE")
            if check_for_no == 'no':
                allow_list.append(uuid)

        for rate, uuid in data:
            # ensure the UUID is in the 'allow_list'
            if uuid in allow_list:
                acr_dict[rate].append(uuid)

        for keys in acr_dict:
            current_acr = keys
            asset_list = []
            for uuid in acr_dict[keys]:
                asset_list.append({"id": uuid})

            try:
                if current_acr:
                    # avoid trying to update assets with "None"
                    if mod == 'set':
                        new_acr = acr
                    elif mod == 'inc':
                        new_acr = int(current_acr) + int(acr)
                        if new_acr > 10:
                            new_acr = 10
                    elif mod == 'dec':
                        new_acr = int(current_acr) - int(acr)
                        if new_acr < 1:
                            new_acr = 1
                    else:
                        pass

                    # check to see if the list goes over 1999 assets then chunk the requests.
                    def chunks(l, n):
                        for i in range(0, len(l), n):
                            yield l[i:i + n]

                    if len(asset_list) > 1999:
                        click.echo("Your request was over 1999 assets and therefore will be chunked up in to groups of "
                                   "1999. You will see a 'success' message per chunk.")
                        for chunks in chunks(asset_list, 1999):
                            lumin_payload = [{"acr_score": int(new_acr), "reason": choice, "note": note, "asset": chunks}]
                            request_data('POST', '/api/v2/assets/bulk-jobs/acr', payload=lumin_payload)
                    else:
                        click.echo("\nProcessing your ACR update requests\n")
                        lumin_payload = [{"acr_score": int(new_acr), "reason": choice, "note": note, "asset": asset_list}]
                        request_data('POST', '/api/v2/assets/bulk-jobs/acr', payload=lumin_payload)
            except TypeError:
                pass

    else:
        click.echo("\nYou can't have a score below 1 or higher than 10\n")
