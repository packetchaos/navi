import click
from .api_wrapper import request_data
from .error_msg import error_msg


@click.group(help="Interact with the Container Security API")
def cs():
    pass


@cs.command(help="Report CVSS 7 or Above")
@click.option('--container', default='', help='Report CVSS 7 or above by \'/repository/image/tag\'')
@click.option('--docker', default='', help='Report CVSS 7 or above by Docker ID')
def report(container, docker):
    if container:
        try:
            data = request_data('GET', '/container-security/api/v2/reports' + str(container))
            try:
                for vulns in data['findings']:
                    if float(vulns['nvdFinding']['cvss_score']) >= 7:
                        click.echo("CVE ID : {}".format(vulns['nvdFinding']['cve']))
                        click.echo("CVSS Score : {}".format(vulns['nvdFinding']['cvss_score']))
                        click.echo("-" * 22)
                        click.echo("\nDescription : \n\n {}".format(vulns['nvdFinding']['description']))
                        click.echo("\nRemediation : \n\n {}".format(vulns['nvdFinding']['remediation']))
                        click.echo("----------------------END-------------------------\n")
            except TypeError:
                click.echo("This Container has no data or is not found")
            except ValueError:
                pass
        except Exception as E:
            error_msg(E)

    if docker:
        try:
            data = request_data('GET', '/container-security/api/v1/reports/by_image?image_id=' + str(docker))

            try:
                for vulns in data['findings']:
                    if float(vulns['nvdFinding']['cvss_score']) >= 7:
                        click.echo("CVE ID : {}".format(vulns['nvdFinding']['cve']))
                        click.echo("CVSS Score : {}".format(vulns['nvdFinding']['cvss_score']))
                        click.echo("-" * 22)
                        click.echo("\nDescription : \n\n {}".format(vulns['nvdFinding']['description']))
                        click.echo("\nRemediation : \n\n {}".format(vulns['nvdFinding']['remediation']))
                        click.echo("----------------------END-------------------------\n")
            except TypeError:
                click.echo("This Container has no data or is not found")
            except ValueError:
                pass
        except Exception as E:
            error_msg(E)


@cs.command(help="Verify if a image passes compliance")
@click.argument('image')
def comply(image):
    try:
        data = request_data('GET', '/container-security/api/v1/policycompliance?image_id=' + str(image))

        click.echo("Status : {}".format(data['status']))
    except Exception as E:
        error_msg(E)
