import boto3
import pprint
import click
import requests
from json import JSONDecodeError


def version():
    return "navi-aws-tags-0.0.1"


def grab_headers():
    access_key = 'Access Key'
    secret_key = 'Secret Key'
    return {'Content-type': 'application/json', 'user-agent': version(), 'X-ApiKeys': 'accessKey=' + access_key + ';secretKey=' + secret_key}


def request_data(method, url_mod, **kwargs):

    # set the Base URL
    url = "https://cloud.tenable.com"

    # check for params and set to None if not found
    try:
        params = kwargs['params']
    except KeyError:
        params = None

    # check for a payload and set to None if not found
    try:
        payload = kwargs['payload']
    except KeyError:
        payload = None

    # Retry the download three times
    for x in range(1, 3):
        try:
            r = requests.request(method, url + url_mod, headers=grab_headers(), params=params, json=payload, verify=True)
            if r.status_code == 200:
                return r.json()

            if r.status_code == 202:
                # This response is for some successful posts.
                click.echo("\nSuccess!\n")
                break
            elif r.status_code == 404:
                click.echo('\nCheck your query...I can\'t find what you\'re looking for {}'.format(r))
                return r.json()
            elif r.status_code == 429:
                click.echo("\nToo many requests at a time...\n{}".format(r))
                break
            elif r.status_code == 400:
                click.echo("\nThe object you tried to create may already exist\n")
                click.echo("If you are changing scan ownership, there is a bug where 'empty' scans won't be moved")
                break
            elif r.status_code == 403:
                click.echo("\nYou are not authorized! You need to be an admin\n{}".format(r))
                break
            elif r.status_code == 409:
                click.echo("API Returned 409")
                break
            elif r.status_code == 504:
                click.echo("\nOne of the Threads and an issue during download...Retrying...\n{}".format(r))
                break
            else:
                click.echo("Something went wrong...Don't be trying to hack me now {}".format(r))
                break
        except ConnectionError:
            click.echo("Check your connection...You got a connection error. Retying")
            continue
        except JSONDecodeError:
            click.echo("Download Error or User enabled / Disabled ")
            continue


def tag_by_aws_id(tag_list, c, v, d):
    try:
        payload = {"category_name": str(c), "value": str(v), "description": str(d), "filters":
            {"asset": {"and": [{"field": "aws_ec2_instance_id", "operator": "eq", "value": str(tag_list)}]}}}
        data = request_data('POST', '/tags/values', payload=payload)
        try:
            value_uuid = data["uuid"]
            cat_uuid = data['category_uuid']
            click.echo("\nI've created your new Tag - {} : {}\n".format(c, v))
            click.echo("The Category UUID is : {}\n".format(cat_uuid))
            click.echo("The Value UUID is : {}\n".format(value_uuid))
        except Exception as E:
            click.echo("Duplicate Tag Category: You may need to delete your tag first\n")
            click.echo("We could not confirm your tag name, is it named weird?\n")
            click.echo(E)
    except:
        click.echo("Duplicate Category")


ec2client = boto3.client('ec2', region_name='us-west-1', aws_access_key_id = 'Access Key',
                         aws_secret_access_key = 'Secret Key')

data = ec2client.describe_tags()
pprint.pprint(data['Tags'])

new_list = []
for tags in data['Tags']:
    key = tags['Key']
    value = tags['Value']

    if value == '':
        value = key

    resource_id = tags['ResourceId']
    description = "AWS Tag"

    if tags['ResourceType'] == 'instance':
        tag_by_aws_id(resource_id, key, value, description)
