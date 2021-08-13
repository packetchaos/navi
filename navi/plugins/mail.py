import click
from .database import new_db_connection
from .send_mail import send_attachment


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
@click.option("--message", default='', help="Email a custom message or use result of a navi command")
@click.option("--to", default='', help="Email address to send to")
@click.option("--subject", default='', help="Subject of the Email")
@click.option("-v", is_flag=True, help="Display a copy of the message")
@click.option("--file", default=None, help="The name of the file you want to attach to the email")
def mail(message, to, subject, v, file):
    try:
        # grab SMTP information
        server, port, from_email, password = grab_smtp()
        if to == '':
            to = input("Please enter the email you wish send this mail to: ")
        if subject == '':
            subject = input("Please enter the Subject of the email : ")

        subject += " - Emailed by navi"

        if v:
            click.echo("Here is a copy of your email that was Sent")
            click.echo(message)

        send_attachment(from_email, to, server, password, port, file, message, subject)

    except Exception as E:
        click.echo("Your Email information may be incorrect")
        click.echo("Run the 'SMTP' command to correct your information")
        click.echo(E)
