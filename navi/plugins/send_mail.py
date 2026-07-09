import os
import base64
import click
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from .database import new_db_connection
try:
    # this is only needed for the Resend email transport.  pip install resend
    import resend
except ImportError:
    resend = 0
    pass


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
            with open(filename, "rb") as attachment:
                payload = attachment.read()
            p = MIMEBase('application', 'octet-stream')

            # To change the payload into encoded form
            p.set_payload(payload)

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


def grab_resend_key(api_key=None):
    # Resolve the Resend API key: explicit arg, then env, then the resend table in navi.db
    if api_key:
        return api_key

    if os.environ.get("RESEND_API_KEY"):
        return os.environ.get("RESEND_API_KEY")

    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT api_key from resend;")
            rows = cur.fetchall()

            for row in rows:
                return row[0]
    except Exception:
        # No resend table yet; that is fine - the caller falls back to SMTP
        pass

    return None


def grab_resend_from(from_email=None):
    # Resolve the from-address: explicit arg, then env, then navi.db, then Resend's testing sender
    if from_email:
        return from_email

    if os.environ.get("HOUNDS_FROM"):
        return os.environ.get("HOUNDS_FROM")

    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT from_email from resend;")
            rows = cur.fetchall()

            for row in rows:
                if row[0]:
                    return row[0]
    except Exception:
        pass

    return "onboarding@resend.dev"


def send_attachment_resend(to_email, subject, message, filename=None, api_key=None, from_email=None):
    # Send an email via the Resend python library - no smtp server, port or mailbox password needed.
    # The key comes from an arg, the RESEND_API_KEY env var, or 'navi config resend' - never the command line.
    if not resend:
        click.echo("\nInformation: The resend package is not installed so the Resend "
                   "transport will not work on this system!"
                   "\n\nInstall it with 'pip install resend'\n")
        return

    key = grab_resend_key(api_key)

    if not key:
        click.echo("\nYou don't have a Resend API key configured!"
                   "\n\nGrab a free key at https://resend.com then either:"
                   "\n\n  export RESEND_API_KEY=<your key>"
                   "\n\n  or run 'navi config resend'"
                   "\n\nSee RESEND_SETUP.md for the one-time setup.\n")
        return

    sender = grab_resend_from(from_email)

    params = {
        "from": sender,
        "to": [to_email],
        "subject": subject,
        "text": message if message else "Report attached - sent by navi"
    }

    # If there is an attachment, base64 encode it and add it to the email.
    if filename:
        with open(filename, "rb") as attachment:
            encoded = base64.b64encode(attachment.read()).decode()

        params["attachments"] = [{"filename": os.path.basename(filename), "content": encoded}]

    try:
        resend.api_key = key
        resend.Emails.send(params)

        click.echo('Email sent via Resend!')
    except Exception as E:
        click.echo("\nSomething went wrong sending through Resend."
                   "\n\nIf you are using the default 'onboarding@resend.dev' sender, Resend only delivers"
                   "\nto the email address that owns the API key. To mail anyone else, verify a domain at"
                   "\nhttps://resend.com/domains and set HOUNDS_FROM or run 'navi config resend'."
                   "\n\nSee RESEND_SETUP.md for details.\n")
        click.echo(E)


def send_report(to_email, subject, message, filename=None, api_key=None, from_email=None,
                smtp_info=None):
    # Single entry point for mailing reports - The Hounds and 'navi action mail' call this.
    # If a Resend key is available (arg, env or config) use Resend; otherwise fall back to SMTP.
    key = grab_resend_key(api_key)

    if key:
        send_attachment_resend(to_email, subject, message, filename=filename,
                               api_key=key, from_email=from_email)
        return

    # No Resend key - legacy SMTP path, untouched behavior
    if smtp_info is None:
        smtp_info = grab_smtp_info()

    if smtp_info:
        server, port, smtp_from, password = smtp_info
        send_attachment(smtp_from, to_email, server, password, port, filename, message, subject)
    else:
        click.echo("\nNo email transport is configured yet - the recipient is the only thing you"
                   "\nneed to supply once an operator does the one-time setup."
                   "\n\nEasiest: grab a free API key at https://resend.com and 'export RESEND_API_KEY=...'"
                   "\nor run 'navi config resend'.  See RESEND_SETUP.md."
                   "\n\nAlternatively configure classic SMTP with 'navi config smtp'.\n")


def grab_smtp_info():
    try:
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
    except Exception:
        pass

    return None
