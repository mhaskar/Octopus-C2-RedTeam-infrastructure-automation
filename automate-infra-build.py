#!/usr/bin/python

import requests
import json
import time
import paramiko
from Crypto.PublicKey import RSA
from os import chmod

public_key_name = "test1.key"
private_key_name = "private.key"
do_token = ""
key_id = ""

infrastructure = {
        # Define your redirectors, choose a name and assign it a domain to be created
        "Redirectors": {
        # The first element of the list should be always the domain name of the redirector
        "HTTPRedirector1": ["myc2redirector.live"],
        # If there is no domain name associated with the instance, leave it blank.
        "HTTPRedirector2": ["myc2redirector2.live"]
    },

# Define the Main C2 name abd Domin
"C2": ["MainC2", "mainc2.live"]
}


# create ssh key
def create_ssh_key():
    global key_id
    # generate ssh keys
    print("[+] Generating SSH keys ..")
    try:
        key = RSA.generate(2048)
        content_file = open(private_key_name, 'wb')
        chmod(private_key_name, 0o600)
        content_file.write(key.exportKey('PEM'))
        pubkey = key.publickey()
        content_file = open(public_key_name, 'wb')
        content_file.write(pubkey.exportKey('OpenSSH'))
        public_key = pubkey.exportKey('OpenSSH')
        headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer %s" % do_token
        }
        data = {
              "name": "Automation SSH Key",
              "public_key": public_key
              }
        request = requests.post("https://api.digitalocean.com/v2/account/keys", headers=headers, json=data)
        response = json.loads(request.text)
        key_id = response["ssh_key"]["id"]
        print("[+] Key ID is : %s" % key_id)
        print("[+] SSH keys generated successfully!")
        return True
    except:
        print("[+] Error while generating keys")
        return False


# Create instance
def deploy_instance(instance_name):
    headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer %s" % do_token
    }
    # Droplet information
    data = {
      "names": [
        instance_name
      ],
      "region": "nyc3",
      "size": "s-1vcpu-1gb",
      "image": "ubuntu-16-04-x64",
      "ssh_keys": [
        key_id
      ],
      "backups": False,
      "ipv6": False,
      "user_data": None,
      "private_networking": None,
      "volumes": None,
      "tags": [
        "RedTeaming"
      ]
    }
    request = requests.post("https://api.digitalocean.com/v2/droplets", headers=headers, json=data)
    response = request.text
    if "created_at" in response:
        print("[+] Droplet %s created successfully!" % instance_name)
        json_response = json.loads(response)
        # print(json_response)
        droplet_id = json_response["droplets"][0]["id"]
        print("[+] Droplet %s id is : %s" % (instance_name, droplet_id))
        print("[+] Getting droplet IP address ..")
        time.sleep(20)
        get_ip_request = requests.get("https://api.digitalocean.com/v2/droplets/%s" % droplet_id, headers=headers)
        json_response = json.loads(get_ip_request.text)
        droplet_ip = json_response["droplet"]["networks"]["v4"][0]["ip_address"]
        print("[+] Droplet %s got public IP %s assigned" % (instance_name, droplet_ip))
        if instance_name in infrastructure["C2"]:
            infrastructure["C2"].append(droplet_id)
            infrastructure["C2"].append(droplet_ip)
        else:
            for redirector in infrastructure["Redirectors"]:
                if instance_name == redirector:
                    infrastructure["Redirectors"][instance_name].append(droplet_id)
                    infrastructure["Redirectors"][instance_name].append(droplet_ip)


def install_octopus(ip, name, c2domain):

    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='root', key_filename=private_key_name)
        print("[+] Connected to %s via ssh" % name)
        print("[+] Generating SSL certficate for %s .." % name)
        ssh.connect(ip, username='root', key_filename=private_key_name)
        setup_certficate = "apt update; apt install certbot -y; apt install apache2 -y;apt-get install python-certbot-apache -y ; certbot --register-unsafely-without-email -m certficate@security.com -d {0} --agree-tos --non-interactive --apache;sudo a2enmod proxy_http".format(c2domain)
        stdin, stdout, stderr = ssh.exec_command(setup_certficate)
        results = stdout.readlines()

        print("[+] Deploying Octopus ..")
        octopus_install_command = "apt update; apt install git -y; git clone https://github.com/mhaskar/Octopus/ /opt/Octopus; cd /opt/Octopus/; apt install python3-pip -y ; export LC_ALL=C ;  pip3 install -r requirements.txt;apt install mono-devel -y"
        stdin, stdout, stderr = ssh.exec_command(octopus_install_command)
        results = stdout.readlines()
        print("[+] Octopus deployed successfully on %s " % name)

    except:
        print("[-] Unable to deploy Octopus")


def link_domain_to_instance(domain, ip, name):
    headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer %s" % do_token
    }
    data = {
          "name": domain,
          "ip_address": ip
          }
    request = requests.post("https://api.digitalocean.com/v2/domains", headers=headers, json=data)
    if domain in request.text:
        print("[+] Domain %s has been linked to the instance %s" % (domain, name))


def setup_redirector(ip, name, domain):
    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='root', key_filename=private_key_name)
        setup_certficate = "apt update; apt install certbot -y; apt install apache2 -y;apt-get install python-certbot-apache -y ; certbot --register-unsafely-without-email -m certficate@security.com -d {0} --agree-tos --non-interactive --apache;sudo a2enmod proxy_http".format(domain)
        stdin, stdout, stderr = ssh.exec_command(setup_certficate)
        results = stdout.readlines()

        c2domain_name = infrastructure["C2"][1]
        edit_configuration_file = 'sed -i "30iSSLEngine On" /etc/apache2/sites-enabled/000-default-le-ssl.conf'
        stdin, stdout, stderr = ssh.exec_command(edit_configuration_file)
        results = stdout.readlines()

        edit_configuration_file = 'sed -i "31iSSLProxyEngine On" /etc/apache2/sites-enabled/000-default-le-ssl.conf'
        stdin, stdout, stderr = ssh.exec_command(edit_configuration_file)
        results = stdout.readlines()

        edit_configuration_file = 'sed -i "32iProxyPass / https://{0}/" /etc/apache2/sites-enabled/000-default-le-ssl.conf'.format(c2domain_name)
        stdin, stdout, stderr = ssh.exec_command(edit_configuration_file)
        results = stdout.readlines()

        edit_configuration_file = 'sed -i "33iProxyPassReverse / https://{0}/" /etc/apache2/sites-enabled/000-default-le-ssl.conf'.format(c2domain_name)
        stdin, stdout, stderr = ssh.exec_command(edit_configuration_file)
        results = stdout.readlines()

        edit_configuration_file = 'service apache2 restart'.format(c2domain_name)
        stdin, stdout, stderr = ssh.exec_command(edit_configuration_file)
        results = stdout.readlines()

        print("[+] Apache and certficate installed on %s" % name)
        print("[+] The redirector %s is up and running!" % name)
    except:
        print("[-] Unable to setup the redirector")


instances = infrastructure["C2"][:1] + [name for name in infrastructure["Redirectors"]]

if create_ssh_key():
    print("[+] Create droplets ..")
    for instance in instances:
        deploy_instance(instance)
    c2name = infrastructure["C2"][0]
    c2domain = infrastructure["C2"][1]
    c2ip = infrastructure["C2"][3]
    link_domain_to_instance(c2domain, c2ip, c2name)
    time.sleep(15)
    install_octopus(c2ip, c2name, c2domain)
    # link MainC2 after installing Octopus
    print("[+] Linking Domains ..")
    # link and setup Redirectors
    for instance in infrastructure["Redirectors"]:
        if infrastructure["Redirectors"][instance][0] != "":
            domain = infrastructure["Redirectors"][instance][0]
            ip = infrastructure["Redirectors"][instance][2]
            link_domain_to_instance(domain, ip, instance)
            print("[+] Setting up redirector/s ..")
            setup_redirector(ip, instance, domain)
