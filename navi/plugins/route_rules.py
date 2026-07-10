"""
Route rules for the vuln_route table.

A "route" is the technology a plugin belongs to (Jenkins, RHEL, Apache Tomcat) so vulns
can be routed to the team that owns that technology.  Routes are derived in three layers,
first match wins:

    1. Rules - regex patterns mapped to a route name.  Users can add their own rules with
       a navi_routes.json file (see load_route_rules below) without touching this code.
    2. CPE - the plugin's CPE string.  'cpe:/a:apache:tomcat' becomes 'Apache Tomcat' and
       the a/o/h part tells us Application vs Operating System for free.
    3. Name fallback - the plugin name with version junk stripped off the end.

Custom rules file (first one found wins):

    1. The file passed to 'navi config routes --file mine.json'  (stored in navi.db)
    2. The NAVI_ROUTES environment variable pointing at a json file
    3. navi_routes.json in the current directory

json format - 'match' is a regex against the plugin name; 'route' names the route and
can use \\1 style backreferences; 'type' is optional:

    {
      "rules": [
        {"match": "^Adobe Acrobat", "route": "Adobe Acrobat", "type": "Application"},
        {"match": "^Security Updates? for ([A-Za-z. ]+?) ?[(]?", "route": "\\1"}
      ],
      "os_routes": ["RHEL", "CentOS", "Custom Linux"]
    }
"""
import os
import re
import json
import click
from .database import new_db_connection

# These replace the old hardcoded if/elif chain - same intent, but data instead of code,
# so the user file can override or extend them
DEFAULT_RULES = [
    {"match": r"^(KB\d|MS\d|MS KB)", "route": "Windows Updates", "type": "Operating System"},
    {"match": r"^Security Updates? for ([A-Za-z. ]+?)\s*(\(|$|\d)", "route": r"\1"},
    {"match": r"^Git for Windows", "route": "Git for Windows"},
    {"match": r"^\.?SVN|^Subversion", "route": "Subversion"},
    {"match": r"^(libcurl|curl)\b", "route": "curl/libcurl"},
    {"match": r"^(RHSA-|RHBA-|Red ?Hat|RHEL)", "route": "RHEL", "type": "Operating System"},
    {"match": r"^CentOS", "route": "CentOS", "type": "Operating System"},
    {"match": r"^LibreOffice", "route": "LibreOffice"},
    {"match": r"^PHP\b", "route": "PHP"},
    {"match": r"^UltraVNC", "route": "UltraVNC"},
    {"match": r"^AIX", "route": "AIX", "type": "Operating System"},
    {"match": r"^Ollama", "route": "Ollama"},
    {"match": r"^(OpenSSH|SSH)\b", "route": "OpenSSH"},
    {"match": r"^(OpenSSL|SSL|TLS)\b", "route": "SSL/TLS"},
    {"match": r"^OpenJDK", "route": "OpenJDK"},
    {"match": r"(Oracle )?Java (SE|JDK|JRE)", "route": "Java"},
    {"match": r"^Jenkins", "route": "Jenkins"},
    {"match": r"^Debian", "route": "Debian", "type": "Operating System"},
    {"match": r"^Ubuntu", "route": "Ubuntu", "type": "Operating System"},
    {"match": r"^(SUSE|SLES|openSUSE)", "route": "SUSE", "type": "Operating System"},
    {"match": r"^(Oracle Linux|EulerOS|Amazon Linux|Alma ?Linux|Rocky ?Linux|Fedora)",
     "route": r"\1", "type": "Operating System"},
    {"match": r"^FreeBSD", "route": "FreeBSD", "type": "Operating System"},
    {"match": r"(Atlassian )?(JIRA|Confluence|Bitbucket|Bamboo)", "route": r"Atlassian \2"},
    {"match": r"^Python\b", "route": "Python"},
    {"match": r"^(VMware )?ESXi?\b", "route": "VMware ESXi", "type": "Operating System"},
    {"match": r"^(Apache )?Tomcat", "route": "Apache Tomcat"},
    {"match": r"^Apache (HTTP|2\.|\d)", "route": "Apache HTTP Server"},
    {"match": r"^(nginx)", "route": "nginx"},
    {"match": r"^(Mozilla )?(Firefox|Thunderbird)", "route": r"Mozilla \2"},
    {"match": r"^(Google )?Chrome", "route": "Google Chrome"},
    {"match": r"^(Microsoft )?Edge", "route": "Microsoft Edge"},
    {"match": r"^macOS|^Mac OS X|^Apple macOS", "route": "macOS", "type": "Operating System"},
    {"match": r"^Cisco IOS", "route": "Cisco IOS", "type": "Operating System"},
]

# Route names that count as Operating System when a rule or CPE didn't already decide
DEFAULT_OS_ROUTES = ["RHEL", "CENTOS", "DEBIAN", "UBUNTU", "AIX", "SUSE", "FREEBSD",
                     "WINDOWS", "WINDOWS UPDATES", "MACOS", "APPLE", "SOLARIS", "HP-UX",
                     "VMWARE ESXI", "CISCO IOS"]

CPE_TYPES = {"a": "Application", "o": "Operating System", "h": "Hardware"}

# Tokens that mark the start of version junk in a plugin name
STOP_WORDS = ["<", "<=", ">", ">=", "=", "PRIOR", "BEFORE", "VERSION", "VERSIONS",
              "MULTIPLE", "VULNERABILITY", "VULNERABILITIES", "REGRESSION", "UPDATE",
              "SEOL", "EOL", "UNSUPPORTED", "DETECTION", "INSTALLED", "RCE", "DOS",
              "XSS", "SQLI", "-"]


def load_route_rules():
    # Merge rules: user file first (it wins), then anything imported into navi.db,
    # then the defaults
    rules = []
    os_routes = list(DEFAULT_OS_ROUTES)

    user_file = None
    if os.environ.get("NAVI_ROUTES"):
        user_file = os.environ.get("NAVI_ROUTES")
    elif os.path.isfile("navi_routes.json"):
        user_file = "navi_routes.json"

    if user_file:
        try:
            with open(user_file) as fobj:
                user_data = json.load(fobj)

            rules.extend(user_data.get("rules", []))

            for os_name in user_data.get("os_routes", []):
                os_routes.append(str(os_name).upper())

            click.echo("Loaded {} custom route rules from {}".format(
                len(user_data.get("rules", [])), user_file))
        except Exception as E:
            click.echo("\nCould not parse {} - fix the json or remove the file. "
                       "Using default rules.\n".format(user_file))
            click.echo(E)

    # rules imported with 'navi config routes'
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT match, route, vuln_type from route_rules ORDER BY rule_order;")
            for row in cur.fetchall():
                rule = {"match": row[0], "route": row[1]}
                if row[2]:
                    rule["type"] = row[2]
                rules.append(rule)
    except Exception:
        # No imported rules; that is fine
        pass

    rules.extend(DEFAULT_RULES)

    return rules, os_routes


def route_from_rules(name, rules):
    # First matching rule wins.  'route' can use backreferences from 'match'
    for rule in rules:
        try:
            found = re.search(rule["match"], name, re.IGNORECASE)
        except re.error:
            continue

        if found:
            try:
                route = found.expand(rule["route"]).strip()
            except (re.error, IndexError):
                route = rule["route"]

            if route:
                return route, rule.get("type")

    return None, None


def route_from_cpe(cpe):
    # 'cpe:/a:apache:tomcat' -> ('Apache Tomcat', 'Application')
    # The cpe column can hold a single cpe or a python list string of several; use the first
    if not cpe or str(cpe) in ("None", "[]", ""):
        return None, None

    cleaned = str(cpe).strip("[]'\" ").split("'")[0].split(",")[0].strip()

    if not cleaned.startswith("cpe:"):
        return None, None

    parts = cleaned.replace("cpe:2.3:", "cpe:/").split(":")

    try:
        part_type = parts[1].strip("/")
        vendor = parts[2]
        product = parts[3]
    except IndexError:
        return None, None

    vuln_type = CPE_TYPES.get(part_type)

    vendor_name = vendor.replace("_", " ").strip()
    product_name = product.replace("_", " ").strip()

    # Don't say 'Jenkins Jenkins' or 'PHP PHP'
    if vendor_name.upper() == product_name.upper() or product_name.upper().startswith(vendor_name.upper()):
        route = product_name
    else:
        route = "{} {}".format(vendor_name, product_name)

    return smart_title(route), vuln_type


def route_from_name(name):
    # Fallback: keep the leading words of the plugin name, stop at version junk
    kept = []
    for token in str(name).replace("(", " (").split():
        bare = token.strip(":,")

        if bare.upper() in STOP_WORDS or bare.startswith("(") or bare.startswith("<"):
            break

        # a digit usually means a version number - but keep names like 7-Zip
        if any(char.isdigit() for char in bare) and kept:
            break

        kept.append(bare)

        if len(kept) == 3:
            break

    if not kept:
        kept = [str(name).split()[0]] if str(name).split() else [str(name)]

    return " ".join(kept)


# cpe products that read as acronyms, so 'php' doesn't become 'Php'
ACRONYMS = ["PHP", "SSL", "TLS", "SSH", "VNC", "AIX", "IOS", "JRE", "JDK", "HTTP",
            "HTTPS", "FTP", "DNS", "SQL", "IIS", "VPN", "SNMP", "RDP", "SMB", "NFS"]


def smart_title(text):
    # Title case but leave acronyms alone: 'redhat enterprise linux' -> 'Redhat Enterprise Linux',
    # 'php' -> 'PHP'
    words = []
    for word in str(text).split():
        if word.isupper() or word.upper() in ACRONYMS:
            words.append(word.upper())
        else:
            words.append(word[0].upper() + word[1:])

    return " ".join(words)


def route_for_plugin(name, cpe, rules, os_routes):
    # The three layers: rules -> cpe -> name.  Returns (route, vuln_type)
    route, vuln_type = route_from_rules(name, rules)

    if not route:
        route, vuln_type = route_from_cpe(cpe)

    if not route:
        route = route_from_name(name)

    if not vuln_type:
        if route.upper() in os_routes:
            vuln_type = "Operating System"
        else:
            vuln_type = "Application"

    return route, vuln_type
