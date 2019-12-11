from .api_wrapper import request_data


def webscan(targets, scanner_id, template):

    # create the scan payload based on the answers we received
    payload = dict(uuid=template, settings={"name": "Scripted Web App Scan of: " + str(targets),
                                            "enabled": "true",
                                            "scanner_id": scanner_id,
                                            "text_targets": targets})
    # setup the scan
    scan_data = request_data('POST', '/scans', payload=payload)

    # pull scan ID after Creation
    scan_id = scan_data["scan"]["id"]

    # let the user no the scan ID so they can pause or stop the scan
    print(targets, " : ", scan_id)
    return
