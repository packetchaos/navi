from .api_wrapper import request_data
from .error_msg import error_msg


def nessus_scanners():
    try:
        data = request_data('GET', '/scanners')

        for scanners in data["scanners"]:
            print(str(scanners["name"]) + " : " + str(scanners["id"]))
    except Exception as E:
        error_msg(E)
