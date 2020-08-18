import click, time
from .database import new_db_connection
from .api_wrapper import request_data
from .send_mail import send_email


def grab_smtp():
    # grab SMTP information
    database = r"navi.db"
    conn = new_db_connection(database)
    with conn:
        cur = conn.cursor()
        cur.execute("SELECT * from smtp;")
        rows = cur.fetchall()

        for row in rows:

            server = row[0]
            port = row[1]
            from_email = row[2]
            password = row[3]

        return server, port, from_email, password


@click.command(help="Mail yourself a Report")
@click.option('-latest', is_flag=True, help='Email Vulnerability Summary Information')
@click.option('-consec', is_flag=True, help="Email Container Security Summary Information")
@click.option('-webapp', is_flag=True, help="Email Web Application Scanning Summary Information")
@click.option("--message", default='', help="Email a custom message or use result of a navi command")
@click.option("--to", default='', help="Email address to send to")
@click.option("--subject", default='', help="Subject of the Email")
@click.option("-v", is_flag=True, help="Display a copy of the message")
def mail(latest, consec, webapp, message, to, subject, v):
    try:
        # grab SMTP information
        server, port, from_email, password = grab_smtp()

        if to == '':
            to = input("Please enter the email you wish send this mail to: ")
        if subject == '':
            subject = input("Please enter the Subject of the email : ")

        subject += " - Emailed by navi Pro"

        # start the message with the proper heading
        msg = "\r\n".join([
            "From: {}".format(from_email),
            "To: {}".format(to),
            "Subject: {}".format(subject),
            "", ])

        if latest:
            data = request_data('GET', '/scans')
            time_list = []
            e = {}
            for x in range(len(data["scans"])):
                # keep UUID and Time together
                # get last modication date for duration computation
                epoch_time = data["scans"][x]["last_modification_date"]
                # get the scanner ID to display the name of the scanner
                d = data["scans"][x]["id"]
                # need to identify type to compare against pvs and agent scans
                scan_type = str(data["scans"][x]["type"])
                # don't capture the PVS or Agent data in latest
                while scan_type not in ['pvs', 'agent', 'webapp', 'lce']:
                    # put scans in a list to find the latest
                    time_list.append(epoch_time)
                    # put the time and id into a dictionary
                    e[epoch_time] = d
                    break

            # find the latest time
            grab_time = max(time_list)

            # get the scan with the corresponding ID
            grab_uuid = e[grab_time]

            # turn epoch time into something readable
            epock_latest = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(grab_time))
            msg += "\nThe last Scan run was at : {}\n".format(epock_latest)

            # pull the scan data
            details = request_data('GET', '/scans/' + str(grab_uuid))

            scanner_name = details["info"]['scanner_name']
            name = details["info"]["name"]
            hostcount = details["info"]["hostcount"]

            msg += "\nThe Scanner name is : {}"\
                "\nThe Name of the scan is {}\n"\
                "The {} host(s) that were scanned are below :\n".format(scanner_name, name, hostcount)

            for x in range(len(details["hosts"])):
                hostname = details["hosts"][x]["hostname"]
                msg += "\n {}".format(hostname)

            start = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_start"]))

            msg += "\n\nScan start : {}".format(start)

            try:
                stop = time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime(details["info"]["scan_end"]))
                msg += "Scan finish : {}".format(stop)

                duration = (details["info"]["scan_end"] - details["info"]["scan_start"]) / 60
                msg += "Duration : {} Minutes".format(duration)
            except:
                click.echo("This scan is still running")

            msg += "\nScan Notes Below : \n\n"

            for x in range(len(details["notes"])):
                title = details["notes"][x]["title"]
                message = details["notes"][x]["message"]
                msg += "{} \n {}".format(title, message)

            msg += "\n\n"

        if consec:
            consec_data = request_data('GET', '/container-security/api/v2/images?limit=1000')
            msg += "\n\nContainer Name - Repo Name - Tag - Docker ID - # of Vulns\n---------------------------------------\n"

            for images in consec_data["items"]:
                name = images["name"]
                docker_id = str(images["imageHash"])
                vulns = str(images["numberOfVulns"])
                repo = str(images["repoName"])
                tag = str(images["tag"])
                msg += "{} : {} : {} : {} : {}\n".format(name, repo, tag, docker_id, vulns)

        if webapp:
            webapp_data = request_data('GET', '/scans')

            # cycle through all of the scans and pull out the webapp scan IDs
            msg += "\n\n Web Application Scan Summary\n-----------------------------------------\n"
            for scans in webapp_data['scans']:

                if scans['type'] == 'webapp':
                    scan_details = request_data('GET', '/scans/' + str(scans['id']))
                    try:
                        hostname = scan_details['hosts'][0]['hostname']
                    except KeyError:
                        hostname = " "
                    try:
                        message = scan_details['notes'][0]['message']
                    except KeyError:
                        message = " "
                    try:
                        critical = scan_details['hosts'][0]['critical']
                    except KeyError:
                        critical = 0
                    try:
                        high = scan_details['hosts'][0]['high']
                    except KeyError:
                        high = 0
                    try:
                        medium = scan_details['hosts'][0]['medium']
                    except KeyError:
                        medium = 0
                    try:
                        low = scan_details['hosts'][0]['low']
                    except KeyError:
                        low = 0

                    if message != "Job expired while pending status.":
                        msg += "\nFQDN : {}\n" \
                               "Scan Message: " \
                               "{}\n\n" \
                               "Vulnerability Summary\n----------------------\n" \
                               "Critical : {}\n" \
                               "High {}\n" \
                               "Medium {}\n" \
                               "Low {}\n".format(hostname, message, critical, high, medium, low)

        if message != '':
            msg += str(message)

        if v:
            click.echo("Here is a copy of your email that was Sent")
            click.echo(msg)

        send_email(from_email, to, msg, server, password, port)
    except Exception as E:
        click.echo("Your Email information may be incorrect")
        click.echo("Run the 'SMTP' command to correct your information")
        click.echo(E)
