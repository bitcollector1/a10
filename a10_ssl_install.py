from neoscripts.a10 import a10_api
import click
import subprocess
import datetime
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Ignore SSL warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
a10_api.requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Define some user variables
datestamp = str(datetime.datetime.now().strftime("%Y-%m-%d_%H.%M"))

if a10_api.os.uname()[0] == 'Linux' or 'Darwin':
    my_path = a10_api.os.getenv("HOME") + "/SSL/"
    backup_path = a10_api.os.getenv("HOME") + "/SSL_BACKUP/"

else:
    print "You shall not pass!\nThis script is for Linux or Mac only"
    exit()

if not a10_api.os.path.exists(my_path):
    a10_api.os.makedirs(my_path)

if not a10_api.os.path.exists(backup_path):
    a10_api.os.makedirs(backup_path)

# Remove any existing certs or keys from a previous run
fileList = a10_api.os.listdir(my_path)
for fileName in fileList:
    a10_api.os.remove(my_path + fileName)


@click.command()
@click.option('--id', help='The Incerts ID for this SAN')
@click.option('--san', help='The new SAN name')
@click.argument('vip_name')
def main(vip_name, id, san):
    """Script to install & update Client SSL Template, certs and key on A10"""

    # initialize san for later call
    if san is None:
        san = '<san>'

    # Strip off FQDN
    vip = a10_api.re.sub('\.linkedin.com', '', vip_name).strip()

    # Grab creds for API calls
    tacacs = a10_api.get_tacacs()
    ldap = a10_api.get_ldap()

    # Query invips for the proper load balancers
    load_balancers = a10_api.find_a10(vip_name)

    try:
        command_url = a10_api.get_sessionid(load_balancers[0] + ".linkedin.com", a10_api.getpass.getuser(), tacacs)
    except KeyError:
        print "\nYour Tacacs key was entered incorrectly, please try again\n"
        exit()

    # Find SSL port and service_group for vip in question, returns list
    ssl_port_info = a10_api.find_ssl_port(command_url, vip)
    service_group = ssl_port_info.pop()
    port = ssl_port_info.pop()

    print "\nAPI shows that https is already configured on the folowing port:\n" + str(port) + "\n"

    # GRAB CERTS & KEY from InCerts API
    ssl_files = a10_api.get_incerts(id, ldap)

    # create unique filenames for certs and key
    ssl_cert_name = (vip + '_' + datestamp + '.crt')
    chain_cert_name = ('digi_intermediate' + '_' + datestamp + '.crt')
    private_key_name = (vip + '_' + datestamp + '.key')

    # Write these files with the new unique names
    f = open(my_path + ssl_cert_name, 'w')
    f.write(str(ssl_files[0].strip()))
    f.close()

    f = open(my_path + chain_cert_name, 'w')
    f.write(str(ssl_files[1].strip()))
    f.close()

    f = open(my_path + private_key_name, 'w')
    f.write(str(ssl_files[2].strip()))
    f.close()

    # Find the IP for the vip host name, needed to do san comparison
    f = a10_api.os.popen("host {0} | awk '{{print $4}}' " .format(vip + ".linkedin.com"))
    vip_ip = f.read().strip()

    # initialize san variables if the DNS does not get set later
    vip_existing_san = "No DNS found! This should be a new SSL template with nothing to compare OR the VIP is unreachable."
    vip_new_san = "\n No DNS found! VIP must be unreachable, please verify confgurations!"
    cert_new_san = "There was no SAN entry found in this specific cert!"

    # Reformat the private-key so SRE's don't have to manually enter the password when restarting services
    f = open(my_path + private_key_name, 'r')
    p = a10_api.os.popen("openssl rsa -in {0} -passin pass:{1} -out {2}" .format(my_path + private_key_name, ssl_files[3], my_path + private_key_name))
    while 1:
        line = p.readline()
        if not line:
            break
        print line

    # CHECK DNS on VIP and compare to new CERT
    p1 = subprocess.Popen("echo '' | openssl s_client -connect {0}:{1} -showcerts |  openssl x509 -text | grep DNS"
                          .format(vip_ip, port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for line in p1.stdout.readlines():
        if "DNS:" in line:
            vip_existing_san = line.strip()

    # Check the DNS on the new CERT you are going to apply to the VIP
    p2 = subprocess.Popen("openssl x509 -text -in {0} | grep DNS".format(my_path + ssl_cert_name), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    for line in p2.stdout.readlines():
        if "DNS:" in line:
            cert_new_san = line.strip()

    # Show the user the difference between the SANS on the current vip and the new cert that will be applied
    print "-" * 160
    print ("The SANS associated to {0} are: \n{1}" .format(vip, vip_existing_san))
    print "-" * 160
    print ("The SANS assocaited to the new CERT are: \n{0}" .format(cert_new_san))
    print "-" * 160

    if vip_existing_san == cert_new_san:
        pass

    else:
        # User will need to acknowledge (y or n) before the program will move forward
        san_question = "\nDo you agree with the proposed changes?(y or n)\n"

        if a10_api.query_yes_no(san_question) is False:
            exit()

    # SSL Template has max char of 63  "-CLIENT-SSL-2016-10-19-14.35" is 28 characters (63-28=35)
    new_ssl_template = vip
    ssl_template_length = len(new_ssl_template)

    if ssl_template_length > 35:
        ssl_template_length = len(new_ssl_template) - 35
        new_ssl_template = new_ssl_template[:-ssl_template_length]

    new_ssl_template = new_ssl_template.upper() + "_CLIENT-SSL_" + datestamp

    # Start making changes to the A10
    for load_balancer in range(len(load_balancers)):

        # Grab hostanmes so we can do IP lookups
        a10_host = load_balancers[load_balancer] + ".linkedin.com"

        print a10_host

        # Grab a new session ID for A10 API calls
        command_url = a10_api.get_sessionid(a10_host, a10_api.getpass.getuser(), tacacs)

        # Import certs and keys into the A10
        a10_api.import_certs(my_path, command_url)

        # Is there an existing SSL template on the vip
        existing_ssl_template = a10_api.find_ssl_template(command_url, vip)

        # Build the new SSL Template
        a10_api.build_clientssl_template(command_url, new_ssl_template, ssl_cert_name, chain_cert_name, private_key_name)

        # Define JSON structure needed to apply new SSL template
        payload = {"name": vip, "vport": {"protocol": 12, "port": port, "client_ssl_template": new_ssl_template}}

        # Apply the new template to the vip
        a10_api.requests.post(command_url + "&method=slb.virtual_server.vport.update&format=json", json=payload, verify=False)

        # Check to see if this is a brand new SSL deployment
        if len(existing_ssl_template) > 1:

            # Find the names of the existing SSL certs and key
            ssl_items = a10_api.find_client_ssl_items(command_url, existing_ssl_template)

            # Export the old SSL certs and key
            a10_api.export_ssl_items(command_url, backup_path, ssl_items)

            private_key = ssl_items.pop()
            chain_cert = ssl_items.pop()
            cert = ssl_items.pop()

            # Create cli deploy commands needed to delete the old SSL certs and key
            commands = "slb ssl-delete private-key " + private_key + "\n slb ssl-delete certificate " + chain_cert + "\n \
                        slb ssl-delete certificate " + cert + "\n"

            # Leave the Template in place if it's being used on another vip (WILDCARDS, etc)
            a10_api.find_duplicate_templates(command_url, existing_ssl_template)

            # Generic API function (cli.deploy) to delete certs and key --> NO API METHOD FOR THIS
            a10_api.requests.post(command_url + "&method=cli.deploy&username=" + a10_api.getpass.getuser() + "&password=" + tacacs + "&grab_config=0", commands,
                                  verify=False)

        # Final verifications after the second load balancer has been confgiured
        if load_balancer == 1:

            # CHECK DNS on VIP after everything is finished
            p1 = subprocess.Popen("echo '' | openssl s_client -connect {0}:{1} -showcerts |  openssl x509 -text | grep DNS"
                                  .format(vip_ip, port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            for line in p1.stdout.readlines():
                if "DNS:" in line:
                    vip_new_san = line.strip()

            # print the final output to the user - they should see the new DNS applied to the vip that was updated.
            print "\n{} was successfully updated with the new template {}\n" .format(vip_name.upper(), new_ssl_template)
            print "-" * 160
            print ("The final SANS associated to {0} after the change are:\n{1}" .format(vip_name, vip_new_san))
            print "-" * 160

            # Begin RESTORE TEMPLATE for emergency rollback
            f = a10_api.os.popen("host {0} | awk '{{print $4}}' " .format(a10_api.os.uname()[1]))
            user_ip = f.read().strip()

            load_user = "scp://{0}@{1}:" .format(a10_api.getpass.getuser(), user_ip)

            print "The following commands will restore the changes if necessary:\n"
            print ("slb ssl-load certificate {0} {1}{2}{3}" .format(cert, load_user, backup_path, cert))
            print ("slb ssl-load certificate {0} {1}{2}{3}" .format(chain_cert, load_user, backup_path, chain_cert))
            print ("slb ssl-load private-key {0} {1}{2}{3}" .format(private_key, load_user, backup_path, private_key))

            print "\nslb template client-ssl " + existing_ssl_template
            print "  cert " + cert
            print "  chain-cert " + chain_cert
            print "  key " + private_key

            print "\nslb virtual-server " + vip_name
            print " port " + str(port) + " https"
            print " no template client-ssl " + new_ssl_template
            print " template client-ssl " + existing_ssl_template
            print "-" * 160

            health_monitor = a10_api.get_healthcheck_contents(command_url, vip, service_group)

            if health_monitor is not None:
                print "\nThe following health monitor is configured: " + health_monitor[0]

                if '</pattern>' in health_monitor[1]:
                    print "There is no expect condition defined"
                    print "\nPlease run the following verification:"
                    print "curl -ILv https://" + san + ":" + str(port) + "\n"
                else:
                    print "The expect condition is : " + health_monitor[1]
                    print "\nPlease run the following verification:"
                    print "curl -ILv https://" + san + ":" + str(port) + health_monitor[0] + "\n"

            else:
                    print "\nDefault ICMP health check is configured, please run the following verification"
                    print "curl -ILv https://" + san + ":" + str(port) + "\n"


if __name__ == '__main__':
    main()

