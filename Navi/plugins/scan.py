import click
from .scanners import nessus_scanners
from .start import start
from .api_wrapper import request_data
from .error_msg import error_msg

@click.command(help="Quickly Scan a Target")
@click.argument('targets')
def scan(targets):
    try:
        print("\nChoose your Scan Template")
        print("1.   Basic Network Scan")
        print("2.   Discovery Scan")
        print("3.   Web App Overview")
        print("4.   Web App Scan")
        option = input("Please enter option #.... ")
        if option == '1':
            template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"
        elif option == '2':
            template = "bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf"
        elif option == '3':
            template = "58323412-d521-9482-2224-bdf5e2d65e6a4c67d33d4322677f"
        elif option == '4':
            template = "09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"
        elif len(option) == 52:
            template = str(option)
        else:
            print("Using Basic scan since you can't follow directions")
            template = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65"

        print("Here are the available scanners")
        print("Remember, don't pick a Cloud scanner for an internal IP address")
        print("Remember also, don't chose a Webapp scanner for an IP address")
        nessus_scanners()
        scanner_id = input("What scanner do you want to scan with ?.... ")

        print("creating your scan of : " + targets + "  Now...")

        payload = dict(uuid=template, settings={"name": "Navi-Pro Created Scan of " + targets,
                                                "enabled": "true",
                                                "scanner_id": scanner_id,
                                                "text_targets": targets})

        # create a new scan
        data = request_data('POST', '/scans', payload=payload)

        # pull scan ID after Creation
        scan = data["scan"]["id"]

        # launch Scan
        start(str(scan))

        # print Scan UUID
        #print("A scan started with UUID: " + data2["scan_uuid"])
        #print("The scan ID is " + str(scan))

    except:
        error_msg()
