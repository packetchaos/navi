from .api_wrapper import request_data

def nessus_scanners():
    try:
        data = request_data('GET', '/scanners')

        for scanners in data["scanners"]:
            print(str(scanners["name"]) + " : " + str(scanners["id"]))
    except:
        print("You may not have access...Check permissions...or Keys")
