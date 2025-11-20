import pprint

import click
from .api_wrapper import request_data, request_no_response


def tag_category_exists(category):
    new_data = request_data("GET", "/api/v1/t1/tags/categories")
    category_id = 'no'
    for cats in new_data["data"]:
        if category == str(cats['name']):
            # Might need to Look for TENABLE_AI if the endpoint changes
            category_id = cats['id']
    return category_id


def grab_tone_asset_list(tag_category, tag_value):
    get_tag_id = tag_value_exists(tag_category, tag_value)

    tagdata = request_data("GET", "/api/v1/t1/tags/{}".format(get_tag_id))

    tagged_assets = tagdata['assets']

    return tagged_assets


def get_all_tags():
    import pprint
    # Filtering out Tenable_io tags to reduce confusion
    # Tenable_AI == Tenable_one
    payload = {
        "filters": [
            {
                "property": "product",
                "value": ["TENABLE_AI"],
                "operator": "="
            }
        ],
        "query": {
            "mode": "simple",
            "text": ""
        }
    }
    tag_details = request_data("POST",
                               "/api/v1/t1/tags/search?extra_properties=tag_category_name, aes_average")
    click.echo("{:37} {:33} {:33} {:11} {:8} {:8} {:7}".format("Asset ID/UUID", "Tag Category", "Tag Value",
                                                               "Tag Product", "Assets", "Findings", "avg.AES"))
    click.echo(150 * "-")
    #pprint.pprint(tag_details)
    for my_tags in tag_details["data"]:
        asset_count = my_tags['asset_count']
        tag_category_name = my_tags['extra_properties']['tag_category_name']
        try:
            aes_average = my_tags['extra_properties']['aes_average']
        except KeyError:
            aes_average = "NONE"
        asset_uuid = my_tags['id']
        tag_value_name = my_tags['name']
        product = my_tags['product']
        total_weakness_count = my_tags['total_weakness_count']
        click.echo("{:37} {:33} {:33} {:11} {:8} {:8} {:7}".format(asset_uuid, tag_category_name,
                                              tag_value_name, product, asset_count, total_weakness_count, aes_average))

    click.echo("\n\n")


def tag_value_exists(tag_category, tag_value):
    # need to add pagination
    offset = 0
    total = 0
    limit = 1000
    tag_id = "no"
    while offset <= total:
        payload= {"limit": limit, "offset": offset}
        value_data = request_data("POST",
                                  "/api/v1/t1/tags/search?extra_properties=tag_category_id,tag_category_name,tag_id",
                                  payload=payload)
        total = value_data['pagination']['total']
        for tag_val in value_data["data"]:
            if tag_value == str(tag_val['name']):
                if tag_category == str(tag_val['extra_properties']['tag_category_name']):
                    tag_id = tag_val['extra_properties']['tag_id']
        offset += 1000

    return tag_id


def tone_create_new_tag(v, d, tag_list, category_id):
    click.echo("Your tag is being created\n")

    try:
        payload = {"tags": {v: d}, "category_id": "{}".format(category_id),
                   "assignment_mode": "asset_ids", "asset_ids": tag_list}

        pprint.pprint(payload)
        request_data('POST', '/api/v1/t1/tags', payload=payload)

    except (KeyError, IndexError):
        click.echo("\nSomething went wrong with the tag creation")


def tone_update_tag(d, tag_list, tag_id):
    click.echo("Your tag is being updated- patch\n")

    try:
        payload = {"tags": {"{}".format(tag_id): {"tag_description": "{}".format(d)}}, "asset_ids_to_add": tag_list,
                   "assignment_mode": "asset_ids"}

        pprint.pprint(payload)

        request_no_response('PATCH', '/api/v1/t1/tags', payload=payload)

    except (KeyError, IndexError):
        click.echo("\nSomething went wrong with the tag creation")


def tone_remove_tag(tag_list, tag_id):
    click.echo("Your tag is being updated; Removing the following assets: {}\n".format(tag_list))

    try:
        payload = {"tags": {"{}".format(tag_id): {}}, "asset_ids_to_remove": tag_list,
                   "assignment_mode": "asset_ids", }

        request_no_response('PATCH', '/api/v1/t1/tags', payload=payload)

    except (KeyError, IndexError):
        click.echo("\nSomething went wrong with the tag creation")


def tag_tone_create_category(c):
    # Create the Tag Category First, then update the tag
    print("Creating a new category")
    payload = {"name": str(c)}
    data = request_data('POST', '/api/v1/t1/tags/categories', payload=payload)
    try:
        cat_uuid = data['id']
        click.echo("\nI've created your tag category - {}\n".format(c))
        click.echo("The Category ID is : {}\n".format(cat_uuid))
        return cat_uuid
    except KeyError:
        click.echo("\nTag created but the uuid wasn't available\n")
        click.echo("Here is the payload navi sent: {}\n".format(payload))
    except TypeError:
        click.echo("*" * 100)
        click.echo("\n\nKNOWN ERROR CONDITION\n\n"
                   "This error occurs when you have the same tag category or tag value name\n"
                   "but it isn't exactly the same name. I.E name vs Name vs naMe\n"
                   "It could be missing a Capital letter or a space.\n"
                   "Try adding a 1 to your tag value and category to test this theory"
                   "report any other challenges to github\n"
                   "Disregard if you didn't get this error using navi tag or navi automate\n\n")
        click.echo("*" * 100)
        exit()


def tone_tag_by_uuid(tag_list, c, v, d):
    import time
    click.echo("\nTagging your Assets in Tenable One.  "
               "Assets will take some time to show up in the UI under the new tag\n")
    # Generator to split IPs into 2000 IP chunks

    def chunks(l, n):
        for i in range(0, len(l), n):
            yield l[i:i + n]

    # We Want to bail if the result is 0 Assets
    if not tag_list:
        click.echo("\nYour tag {}:{} resulted in 0 Assets, therefore the tag wasn't created\n".format(c, v))
        exit()

    else:
        # Check the Categories; Does the category exist?
        check_catergory_id = tag_category_exists(c)

        # Evaluate if the Tag needs to be created or updated
        if check_catergory_id == "no":
            click.echo("There is no Tag category")
            # Create a category and grab the ID
            category_id = tag_tone_create_category(c)

            # Create the new tag with the category ID
            if len(tag_list) > 5000:
                # break the list into 2000 IP chunks
                click.echo("\nYour Tag results were over 5000 assets; breaking up the api requests\n")
                pass_one = 0
                for chunks in chunks(tag_list, 5000):
                    if pass_one == 1:
                        check_tag_id = tag_value_exists(c, v)
                        # Each 5000 assets after, update the tag
                        time.sleep(5)
                        tone_update_tag(d, chunks, check_tag_id)
                    else:
                        # First 5000, create the tag
                        tone_create_new_tag(v, d, chunks, category_id)
                        pass_one += 1
            else:
                tone_create_new_tag(v, d, tag_list, category_id)

        else:
            # Confirmed we have a category, do we have a tag? if so, grab the ID
            check_tag_id = tag_value_exists(c, v)

            if check_tag_id == "no":
                # Got a category ID but no Tag ID. Let's create a new tag
                if len(tag_list) > 5000:
                    # break the list into 2000 IP chunks
                    click.echo("\nYour Tag results were over 5000 assets; breaking up the api requests\n")
                    pass_one = 0
                    for chunks in chunks(tag_list, 5000):
                        if pass_one == 1:
                            time.sleep(5)
                            check_tag_id = tag_value_exists(c, v)
                            # Each 5000 assets after, update the tag
                            time.sleep(5)
                            tone_update_tag(d, chunks, check_tag_id)
                        else:
                            # First 5000, create the tag
                            tone_create_new_tag(v, d, chunks, check_catergory_id)
                            pass_one += 1
                else:
                    tone_create_new_tag(v, d, tag_list, check_catergory_id)

            else:
                # Check to see if the List of UUIDs is over 5000 (API Limit)
                if len(tag_list) > 5000:
                    click.echo("\nYour Tag results were over 5000 assets; breaking up the api requests\n")
                    # break the list into 2000 IP chunks
                    for chunks in chunks(tag_list, 5000):
                        tone_update_tag(d, chunks, check_tag_id)
                else:
                    # If the Chunk is less than 5000, simply update it.
                    tone_update_tag(d, tag_list, check_tag_id)