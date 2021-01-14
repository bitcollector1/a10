import requests
import getpass
import sys
import re
import os


"""
A10 API Library Calls
"""


def get_ldap():
    print "\nPlease enter your LDAP password for InCerts"
    ldap = getpass.getpass()
    return ldap


def get_tacacs():
    print "\nPlease enter your Tacacs password for login to A10"
    tacacs = getpass.getpass()
    return tacacs


def find_a10(vip_name):

    sites = ("ela4", "lca1", "lva1", "lsg1", "ltx1", "lor1")

    # Strip off FQDN
    vip = re.sub('\.linkedin.com', '', vip_name).strip()

    # Looking for which enviornment the vip is located: lca1-s1-logstash.stg
    enviornment = vip.split('.').pop()

    # Stage vips are actually part of the corp fabric so we need to translate
    if 'stg' in enviornment:
        enviornment = "corp"

    elif "prod" in enviornment:
        enviornment = "prod"

    # Find the location to build fabric statement
    for site in sites:
        if site in vip_name:
            location = site
            break
        elif "ei3" in vip_name:
            location = "lva1"
        elif "ei2" in vip_name:
            location = "ltx1"
        elif "ei" in vip_name:
            location = "lca1"

    # Build the fabric statement for invips CLI below
    fabric = '{0}-{1}' .format(enviornment, location)

    try:
        # query invips for proper load balancers and print output to user
        f = os.popen("invips2 -f {0} search vip {1} | awk '/lb/ {{print $4}}' " .format(fabric, vip))
        load_balancer = f.read().strip()
        load_balancers = load_balancer.split('\n')
        print ("\nThe load balancers to be updated are:\n {0} \n {1}" .format(load_balancers[0], load_balancers[1]))
        return load_balancers

    # invips-cli was not able to query the database for the correct load balancers
    except IndexError:
        load_balancers = ['standby', 'primary']
        load_balancers[0] = raw_input("\nPlease enter the Standby load balancer\n")
        load_balancers[1] = raw_input("\nPlease enter the Primary load balancer\n")
        return load_balancers


def get_a10_ip(a10_host):
    f = os.popen("host {0}.linkedin.com | awk '{{print $4}}' " .format(a10_host))
    a10_ip = f.read().strip()
    return a10_ip


def get_sessionid(a10_host, script_user, tacacs):

    try:
        # Grab the session ID via Requests
        session_id_data = requests.get("https://" + a10_host + "/services/rest/V2/?" + "method=authenticate&username={0}&password={1}&format=json"
                                       .format(script_user, tacacs), verify=False).json()
    except requests.exceptions.ConnectionError:
        print "\nThis vip is not reachable via desktop due to ACL's, please run from netops box"
        exit()

    # Format the command url for future API calls
    command_url = "https://" + a10_host + "/services/rest/V2/?" + "&session_id=" + session_id_data['session_id']

    return command_url


def find_ssl_port(command_url, vip):

    # Search for a specific VIP & read JSON so we can grab data easily
    vip_data = requests.get(command_url + "&format=json&method=slb.virtual_server.search&name=" + vip, verify=False).json()

    # Grab all of the ports configured on the vip
    vip_vport_list = vip_data['virtual_server']['vport_list']

    # check to see if https is configured on vip, client_ssl_template is a unique attribute for https
    for i in vip_vport_list:
        if 'client_ssl_template' in i:
            ssl_port_info_dict = i

    try:
        port = ssl_port_info_dict.get('port', "default value")
        service_group = ssl_port_info_dict.get('service_group', "default value")
        ssl_port_info = [port, service_group]
        return ssl_port_info

    except NameError:
        print "\nhttps is not currently defined on the vip, please configure https and run again.\n"
        exit()


def get_incerts(incerts_id, ldap):

    # If click option was not used to provide ID, prompt the user for URL
    if incerts_id is None:
        # extract the CERT ID from the URL pasted into JIRA ticket
        incerts_url_id = raw_input("\nPlease paste in the incerts URL to download CERT/KEY\n")

        # strip the ID from the URL
        id = incerts_url_id.split("/")
        incerts_id = id[-3]

    try:
        incerts_json = requests.get('https://incerts.corp.linkedin.com/api/v1/certificate/download/?id=' + incerts_id, auth=(getpass.getuser(), ldap)).json()

    except:
        print "\nYour LDAP password is incorrect or you are not authorized to use incerts\n"
        exit()

    try:
        # Assign the variables from the JSON structure
        ssl_cert = incerts_json["certificates"][0]["certificate"]
        chain_cert = incerts_json["certificates"][0]["intermediate_certificate"]
        private_key = incerts_json["certificates"][0]["key"]
        ssl_password = incerts_json["certificates"][0]["password"]

        ssl_files = [ssl_cert, chain_cert, private_key, ssl_password]
        return ssl_files

    except KeyError:
        print "There was a problem downloading from incerts"
        exit()


def query_yes_no(san_question, default="no"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(san_question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def import_certs(my_path, command_url):

    method = "method=slb.ssl.upload"
    listing = os.listdir(my_path)
    for infile in listing:
        cert = open(my_path + infile, "r")
        for i in cert:
            if "BEGIN CERTIFICATE" in i:
                type = "crt"
                params = {'file': open(my_path + infile, 'rb')}
                break
            elif "BEGIN RSA PRIVATE KEY" in i:
                type = "key"
                params = {'file': open(my_path + infile, 'rb')}
                break
            elif "BEGIN ENCRYPTED PRIVATE KEY" in i:
                type = "key"
                params = {'file': open(my_path + infile, 'rb')}
                break
            else:
                type = "none"
                break
        if type == "crt":
            request = str(command_url + "&" + method.__str__() + "&type=certificate")
        elif type == "key":
            request = str(command_url + "&" + method.__str__() + "&type=key")
        else:
            continue

        try:
            requests.post(request, files=params, verify=False)

        except:
            print "error with " + infile
            continue


def find_ssl_template(command_url, vip):

    # search for a specific VIP and return JSON
    vip_data = requests.get(command_url + "&format=json&method=slb.virtual_server.search&name=" + vip, verify=False).json()

    # Grab JSON all of the ports configured on the vip
    vip_vport_list = vip_data['virtual_server']['vport_list']

    # Loop through list and create a new dictionary when condition is found
    for i in vip_vport_list:
        if 'client_ssl_template' in i:
            ssl_port_info_dict = i

    for k, v in ssl_port_info_dict.items():
        if k == 'client_ssl_template':
            existing_template_name = v

    return existing_template_name


def build_clientssl_template(command_url, ssl_template_name, ssl_cert, chain_cert, private_key):

    r = requests.get(command_url + "&method=slb.template.client_ssl.create&name=" + ssl_template_name + "&cert_name=" + ssl_cert +
                                   "&chain_name=" + chain_cert + "&key_name=" + private_key, verify=False)

    return r.text


def find_client_ssl_items(command_url, existing_template_name):

    # Build the URL needed to search for a specific Client SSL Template --> Return XML
    ssl_template = requests.get(command_url + "&method=slb.template.client_ssl.search&name=" + existing_template_name, verify=False)

    existing_cert_match = re.search(r"<cert_name>(.+?)<", ssl_template.text)
    existing_chain_match = re.search(r"<chain_name>(.+?)<", ssl_template.text)
    existing_key_match = re.search(r"<key_name>(.+?)<", ssl_template.text)

    existing_cert = existing_cert_match.group(1)
    existing_chain = existing_chain_match.group(1)
    existing_key = existing_key_match.group(1)

    ssl_items = [existing_cert, existing_chain, existing_key]

    return ssl_items


def export_ssl_items(command_url, backup_path, ssl_items):

    ssl_cert = requests.get(command_url + "&method=slb.ssl.download&type=certificate&file_name=" + ssl_items[0], verify=False)
    ssl_cert_file = backup_path + ssl_items[0]

    f = open(ssl_cert_file, 'w')
    f.write(ssl_cert.text.encode('utf-8'))
    f.close()

    ssl_chain = requests.get(command_url + "&method=slb.ssl.download&type=certificate&file_name=" + ssl_items[1], verify=False)
    ssl_chain_file = backup_path + ssl_items[1]

    f = open(ssl_chain_file, 'w')
    f.write(ssl_chain.text.encode('utf-8'))
    f.close()

    ssl_key = requests.get(command_url + "&method=slb.ssl.download&type=key&file_name=" + ssl_items[2], verify=False)
    ssl_key_file = backup_path + ssl_items[2]

    f = open(ssl_key_file, 'w')
    f.write(ssl_key.text.encode('utf-8'))
    f.close()


def find_duplicate_templates(command_url, existing_ssl_template):

    # Grab all the vips configured on the load balancer
    vips = requests.get(command_url + "&method=slb.virtual_server.getAll&format=json", verify=False).json()

    # find how many vips we have configured so we can search each vip element individually
    vip_count = len(vips['virtual_server_list'])
    vip_count -= 1

    # Initilize list so we can append below
    ssl_template_list = []

    # Search through vip vport_list elements digging for Template information
    while vip_count >= 0:
        vip_vport_list = vips['virtual_server_list'][vip_count]['vport_list']
        vip_count -= 1

        for i in vip_vport_list:
            if 'client_ssl_template' in i:
                port_info_dict = i

                var = port_info_dict.get("client_ssl_template")
                ssl_template_list.append(str(var))

    if existing_ssl_template in ssl_template_list:
        print "Found another vip using the old SSL template, leaving old template in place"

    else:
        # no other vips using this template so it is safe to delete the old template
        requests.get(command_url + "&method=slb.template.client_ssl.delete&name=" + existing_ssl_template, verify=False)


def get_healthcheck_contents(command_url, vip, service_group):

    service_group_data = requests.get(command_url + "&format=json&method=slb.service_group.search&name=" + service_group, verify=False).json()

    # Grab a Real Server, the first member is fine since service groups are unique to a port
    real_server = service_group_data['service_group']['member_list'][0]['server']

    real_server_data = requests.get(command_url + "&method=slb.server.search&name=" + real_server + "&format=json", verify=False).json()

    port_list = real_server_data['server']['port_list']

    counter = len(port_list)

    while counter > 0:
        counter -= 1
        health_check = port_list[counter].get('health_monitor')

    if 'default' not in health_check:

        health_search_data = requests.get(command_url + "&method=slb.hm.search&name=" + health_check, verify=False)

        try:
            # no url field if the port is TCP!!
            health_check_find = re.search(r"<url>(.+?)<", health_search_data.text)
            expect_find = re.search(r"<expect><pattern>(.+?)<", health_search_data.text)

            health_check_string = health_check_find.group(1)
            expect = expect_find.group(1)

            health_check_list = health_check_string.split(" ")
            del health_check_list[0]

            health_check = health_check_list[0]

            health_monitor = health_check, expect

            return health_monitor

        except AttributeError:
            print "There was no healthcheck found configured on the real servers\n"

