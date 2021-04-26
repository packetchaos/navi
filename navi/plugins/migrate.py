import boto3
import click
from .database import db_query
from .tag import tag_by_uuid


def organize_aws_keys(aws_ec2):
    aws_tags = {}  # Dictionary of Tag key/Value pairs
    aws_keys = {}  # Dictionary of Values/List of Instance Ids
    for tags in aws_ec2['Tags']:
        if tags['ResourceType'] == 'instance':
            aws_key = tags['Key']
            aws_value = tags['Value']
            resource_id = tags['ResourceId']

            # Tenable IO Requires a Key and a Value; AWS does not.  In this case we just use the key as both
            if aws_value == '':
                aws_value = aws_key

            # Creates a new value dict if one doesn't exist, adds to the value list if one does.
            try:
                aws_keys[aws_value].append(resource_id)
            except KeyError:
                aws_keys[aws_value] = [resource_id]

            # creates a key dict if one doesn't exist, adds the value dict if one does
            if aws_key not in aws_tags:
                aws_tags[aws_key] = {aws_value: aws_keys[aws_value]}
            else:
                aws_tags[aws_key].update({aws_value: aws_keys[aws_value]})

    return aws_tags


@click.command(help="Migrate AWS Tags to T.io tags by Instance ID")
@click.option("--region", default="", required=True, help="AWS Region")
@click.option("--a", default="", required=True, help="Access Key")
@click.option("--s", default="", required=True, help="Secret Key")
def migrate(region, a, s):
    if not a or not s or not region:
        click.echo("You need a region, access key and secret Key")
        exit()
    # Authentication
    ec2client = boto3.client('ec2', region_name=region, aws_access_key_id=a, aws_secret_access_key=s)

    # Grab All of the tags in the Account
    aws_ec2 = ec2client.describe_tags()

    # Send the data to get organized into a neat dictionary of Lists
    aws_organized_tags = organize_aws_keys(aws_ec2)

    # Grab the Key, value and the new list out of the dict to send to the tagging function
    for key, value in aws_organized_tags.items():
        for z, w in value.items():
            uuid_list = []
            for instance in w:
                # Look up the UUID of the asset
                db = db_query("select uuid from assets where aws_id='{}';".format(instance))
                for record in db:
                    uuid_list.append(record[0])
            description = "AWS Tag by Navi"

            print("Creating a Tag named - {} : {} - with the following ids {}".format(key, z, w))

            tag_by_uuid(uuid_list, key, z, description)
