import time
from .api_wrapper import request_data


def scan_details(uuid):
    # pull the scan data
    details = request_data('GET', '/scans/' + str(uuid))

    print("\nThe Scanner name is : " + str(details["info"]['scanner_name']))
    print("\nThe Name of the scan is " + str(details["info"]["name"]))
    print("\nThe Scan ID is " + str(uuid))
    print("\nThe " + str(details["info"]["hostcount"]) + " host(s) that were scanned are below :\n")
    for hosts in details["hosts"]:
        print(hosts["hostname"])

    start_time = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_start"]))
    print("\nscan start : " + start_time)
    try:
        stop = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_end"]))
        print("scan finish : " + stop)

        duration = (details["info"]["scan_end"] - details["info"]["scan_start"]) / 60
        print("Duration : " + str(duration) + " Minutes")
    except KeyError:
        print("This scan is still running")
    print("Scan Notes Below : ")
    for notes in details["notes"]:
        print("         " + notes["title"])
        print("         " + notes["message"] + "\n")
    return
