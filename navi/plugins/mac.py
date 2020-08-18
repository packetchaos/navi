import click
import requests
from .error_msg import error_msg


@click.command(help="Enter in a Mac Address to find the Manufacturer")
@click.argument('address')
def mac(address):
    try:
        api_token = "Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtYWN2ZW5kb3JzIiwiZXhwIjoxODU3NzYzODQ1LCJpYXQiOjE1NDMyNjc4NDUsImlzcyI6Im1hY3ZlbmRvcnMiLCJqdGkiOiIzYWNiM2Q0YS1lZjQ2LTQ3NWUtYWJiZS05M2NiMDlkMDU5YzIiLCJuYmYiOjE1NDMyNjc4NDQsInN1YiI6Ijk0NyIsInR5cCI6ImFjY2VzcyJ9.a_dLSCJq-KLjOQL52ZgiuDY08_YE5Wl7QhAJpDpHOKoIesGeMRnPGZAx3TgtfwyQVyy6_ozhy447GGdfKyjDXw"

        headers = {'Content-type': 'application/json', 'Authorization': api_token}

        url = "https://api.macvendors.com/v1/lookup/"

        r = requests.request('GET', url + address, headers=headers, verify=True)
        data = r.json()
        click.echo("Assignment Group:")
        click.echo(data['data']['assignment'])

        click.echo("\nOrganization name:")
        click.echo(data['data']['organization_name'])
    except ConnectionError as E:
        error_msg(E)
    except KeyError:
        click.echo("Mac Address information Not found")
