import click
import smtplib


def send_email(from_email, to_email, msg, mail_server, password, port):
    click.echo(msg)
    try:
        server = smtplib.SMTP(mail_server, port)
        server.ehlo()
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg)
        server.close()

        click.echo('Email sent!')
    except Exception as E:
        click.echo('\nSomething went wrong...Your email information may be incorrect\n')
        click.echo("For now you must use an 'less secure' setting in Gmail for this feature."
                   "\n I'm working on a more secure option.")
        click.echo(E)
