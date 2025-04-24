import click
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


def send_attachment(from_email, to_email, mail_server, password, port, filename, message, subject):
    try:
        server = smtplib.SMTP(mail_server, port)
        server.ehlo()
        server.starttls()
        server.login(from_email, password)

        msg2 = MIMEMultipart()
        msg2['Subject'] = subject
        msg2['From'] = from_email
        msg2['To'] = to_email
        msg2.attach(MIMEText(message, 'plain'))

        # If there is an attachment, add it to the email.
        if filename:
            attachment = open(filename, "rb")
            p = MIMEBase('application', 'octet-stream')

            # To change the payload into encoded form
            p.set_payload(attachment.read())

            # encode into base64
            encoders.encode_base64(p)

            p.add_header('Content-Disposition', "attachment; filename= %s" % filename)

            # attach the instance 'p' to instance 'msg'
            msg2.attach(p)

        server.sendmail(from_email, to_email, msg2.as_string())
        server.close()

        click.echo('Email sent!')
    except Exception as E:
        click.echo('\n\nSomething went wrong...Your email information may be incorrect')
        click.echo("\n\nThis feature may not work with Gmail due to some security settings: Try GMX mail"
                   "\n\nIf you are seeing this message: here are two things to try."
                   "\n\nOne in GMX or other email clients you may need to enable POP from settings. "
                   "\n\nTwo, make sure your smtp settings are correct."
                   "\n\nUse 'navi explore data query' command to query the smtp table.\n\n")
        click.echo(E)
