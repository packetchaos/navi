from .api_wrapper import request_data
from .error_msg import error_msg


def nessus_scanners():
    try:
        data = request_data('GET', '/scanners')
        print("\nScanner Name".ljust(36), "Scanner ID".ljust(20), "Scanner UUID")
        print("-" * 100)
        for scanners in data["scanners"]:
            print(str(scanners["name"].ljust(35)), str(scanners["id"]).ljust(20), str(scanners['uuid']))
        print()
    except Exception as E:
        error_msg(E)
