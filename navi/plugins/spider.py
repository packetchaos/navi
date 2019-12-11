import click
import csv
from .scanners import nessus_scanners
from .error_msg import error_msg
from .web_scan import webscan


@click.command(help="Create a Web App scan from a CSV file")
@click.argument('csv_input')
def spider(csv_input):
    try:
        # request the User to choose a Scan Template
        print("\nChoose your Scan Template")
        print("1.  Web App Overview")
        print("2   Web App Scan")

        # capture the choice
        option = input("Please enter option #.... ")

        # set the Template ID based on their choice
        if option == '1':
            # Web App Overview template ID
            template = "58323412-d521-9482-2224-bdf5e2d65e6a4c67d33d4322677f"

        elif option == '2':
            # Web App Scan template ID
            template = "09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"

        # Template ID is 52 chars long; let the user put in their own policy ID
        elif len(option) == 52:
            template = str(option)

        # if anything else is entered outside of these options, make it a Web App policy
        else:
            print("Using Web App scan since you can't follow directions")
            template = "09805055-a034-4088-8986-aac5e1c57d5f0d44f09d736969bf"

        # Grab the scanners so the user can choose which scanner to use
        print("Here are the available scanners")
        print("Remember, Pick A Web App scanner! NOT a Nessus Scanner. ")
        nessus_scanners()

        # capture the users choice - putting in the wrong scanner will cause and error that we haven't programed to catch
        scanner_id = input("What scanner do you want to scan with ?.... ")

        with open(csv_input, 'r', newline='') as csv_file:
            web_apps = csv.reader(csv_file)

            for app in web_apps:
                webscan(app[0], scanner_id, template)
    except Exception as E:
        error_msg(E)
