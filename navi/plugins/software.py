import click
from .dbconfig import create_software_table, new_db_connection
from .database import db_query, insert_software, drop_tables
import pprint


@click.group(help="Generate a report of software in your environment")
def software():
    pass

@software.command(help="Create the database table and populate the software data")
def generate():
    database = r'navi.db'
    new_conn = new_db_connection(database)
    drop_tables(new_conn, "software")
    create_software_table()
    #massive_list_of_software = []
    #sft_uuid_pairs = []
    uuid_list = []
    soft_dict = {}
    software_data = db_query("select output, asset_uuid from vulns where plugin_id='22869'")

    # 22869 Parser
    for host in software_data:
        try:
            # split plugin data by "|"
            for pkg in str(host[0]).split("|"):
                pkg_name = str(pkg).split(" ")[-1]
                # print(pkg_name)
                if pkg_name != "the":
                    #massive_list_of_software.append(pkg_name)
                    #sft_uuid_pairs.append([host[1], pkg_name, "22869"])

                    if pkg_name not in soft_dict:
                        soft_dict[pkg_name] = [host[1]]
                    else:
                        soft_dict[pkg_name].append(host[1])

        except IndexError:
            pkg_name = str(str(host).split("|")[2]).split(" ")[2]
            #massive_list_of_software.append(pkg_name)
            if pkg_name not in soft_dict:
                soft_dict[pkg_name] = [host[1]]
            else:
                soft_dict[pkg_name].append(host[1])

    with new_conn:
        new_list = []
        for item in soft_dict.items():
            #print(item[1])
            # Save the uuid list as a string
            new_list = [item[0], str(item[1]), "22869"]
            insert_software(new_conn, new_list)

    # pprint.pprint(set(massive_list_of_software))
    total = len(soft_dict)
    asset_evaluated = db_query("select count(output) from vulns where plugin_id='22869'")[0][0]
    assets_not_evaluated = len(set(db_query("select asset_uuid from vulns where plugin_id !='22869'")))
    #pprint.pprint(sft_uuid_pairs)
    #print("*" * 150)
    #print()
    print("\nUnique Software total is:", total)
    print("\nAssets evaluated:", asset_evaluated)
    print("\nAssets Not Evaluated:", assets_not_evaluated)