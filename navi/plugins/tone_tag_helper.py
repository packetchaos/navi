import click
from .api_wrapper import request_data, request_no_response


def tag_category_exists(category):
    new_data = request_data("GET", "/api/v1/t1/tags/categories")
    category_id = 'no'
    for cats in new_data["data"]:
        if category == str(cats['name']):
            category_id = cats['id']
    return category_id


def get_all_tags():
    import pprint
    payload = {"limit": 1000}
    tag_details = request_data("POST", "/api/v1/t1/tags/search", payload=payload)
    pprint.pprint(tag_details)


def tag_value_exists(tag_category, tag_value):
    # need to add pagination
    payload = {"limit": 1000}
    tag_id = "no"
    value_data = request_data("POST",
                              "/api/v1/t1/tags/search?extra_properties=tag_category_id,tag_category_name,tag_id",
                              payload=payload)

    for tag_val in value_data["data"]:
        if tag_value == str(tag_val['name']):
            if tag_category == str(tag_val['extra_properties']['tag_category_name']):
                tag_id = tag_val['extra_properties']['tag_id']

    return tag_id


def tone_create_new_tag(c, v, d, tag_list, category_id):
    click.echo("Your tag is being created\n")

    try:
        payload = {"tags": {v: d}, "category_id": "{}".format(category_id),
                   "assignment_mode": "asset_ids", "asset_ids": tag_list}
        print(payload)
        request_data('POST', '/api/v1/t1/tags', payload=payload)

    except (KeyError, IndexError):
        click.echo("\nSomething went wrong with the tag creation")


def tone_update_tag(d, tag_list, tag_id):
    click.echo("Your tag is being updated\n")

    try:
        payload = {"tags": {"{}".format(tag_id): {"tag_description": "{}".format(d)}}, "asset_ids_to_add": tag_list,
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
    print("\nTagging your Assets in Tenable One.  Assets will take some time to show up in the UI under the new tag\n")
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
            print("There is no Tag category; Creating a New Tag Category")
            # Create a category and grab the ID
            category_id = tag_tone_create_category(c)

            # Create the new tag with the category ID
            tone_create_new_tag(c, v, d, tag_list, category_id)
        else:
            # Confirmed we have a category, do we have a tag? if so, grab the ID
            check_tag_id = tag_value_exists(c, v)

            if check_tag_id == "no":
                print("am i here", check_catergory_id)
                # Got a category ID but no Tag ID. Let's create a new tag
                tone_create_new_tag(c, v, d, tag_list, check_catergory_id)
                ''' This needs to be broken into groups of 5000'''
            else:
                # Check to see if the List of UUIDs is over 5000 (API Limit)
                if len(tag_list) > 5000:
                    # break the list into 2000 IP chunks
                    for chunks in chunks(tag_list, 5000):
                        tone_update_tag(chunks, check_tag_id)
                else:
                    # If the Chunk is less than 5000, simply update it.
                    tone_update_tag(tag_list, check_tag_id)