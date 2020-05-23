#!/usr/bin/python

import requests
import json
import time
import paramiko
from Crypto.PublicKey import RSA
from os import chmod

public_key_name = "test1.key"
do_token = ""
main_c2_name = "MainC2"
redirector_name = "C2Redirector"
redirector_domain = "myc2redirector.live"
key_id = ""

infrastructure = {
"Redirectors": {"Name1": "Domain1"},
"C2": "C2Name"
}

# create ssh key
def create_ssh_key():
    global key_id
    # generate ssh keys
    print("[+] Generating SSH keys ..")
    try:
        key = RSA.generate(2048)
        content_file = open("private.key", 'wb')
        chmod("private.key", 0o600)
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

# create two instances with the ssh key

def create_instances():
    global api_url
    headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer %s" % do_token
    }
    data = {
      "names": [
        main_c2_name,
        redirector_name
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
        print("[+] %s droplet created successfully!" % main_c2_name)
        print("[+] %s droplet created successfully!" % redirector_name)
        json_response = json.loads(response)
        main_c2_droplet_id = json_response["droplets"][0]["id"]
        redirector_doplet_id = json_response["droplets"][1]["id"]
        print("[+] %s droplet ID is %s " % (main_c2_name, main_c2_droplet_id))
        print("[+] %s droplet ID is %s " % (redirector_name, redirector_doplet_id))
        print("[+] Getting droplets IPs ..")
        headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer %s" % do_token
        }
        print("[+] We have to wait 60 seconds to make sure that everything is deployed ..")
        time.sleep(60)
        main_c2_ip_request = requests.get("https://api.digitalocean.com/v2/droplets/%s" % main_c2_droplet_id, headers=headers)
        main_c2_ip_response = json.loads(main_c2_ip_request.text)
        main_c2_ip = main_c2_ip_response["droplet"]["networks"]["v4"][0]["ip_address"]

        redirector_ip_request = requests.get("https://api.digitalocean.com/v2/droplets/%s" % redirector_doplet_id, headers=headers)
        redirector_ip_response = json.loads(redirector_ip_request.text)
        redirector_ip = redirector_ip_response["droplet"]["networks"]["v4"][0]["ip_address"]
        print("[+] %s ip is : %s" % (main_c2_name, main_c2_ip))
        print("[+] %s ip is : %s" % (redirector_name, redirector_ip))
        print("[+] Deploying Octopus on %s .." % main_c2_name)
        install_octopus(main_c2_ip, main_c2_name)
        link_domain_to_redirector(redirector_ip)
        setup_redirector(redirector_ip, redirector_name)

    else:
        print("[-] Error while creating the droplet!")
        exit()

# link redirector_domain to the 2nd server

def link_domain_to_redirector(redirector_ip):
    headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer %s" % do_token
    }
    data = {
          "name": redirector_domain,
          "ip_address": redirector_ip
          }
    request = requests.post("https://api.digitalocean.com/v2/domains", headers=headers, json=data)
    if redirector_domain in request.text:
        print("[+] Domain %s has been linked to the redirector %s" % (redirector_domain, redirector_name))

# login to the 1st server and install Octopus

def install_octopus(ip, name):

    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    #try:
    ssh.connect(ip, username='root', key_filename='private.key')
    print("[+] Connected to %s via ssh" % name)
    print("[+] Deploying Octopus ..")
    octopus_install_command = "apt update; apt install git -y; git clone https://github.com/mhaskar/Octopus/ /opt/Octopus; cd /opt/Octopus/; apt install python3-pip -y ; export LC_ALL=C ;  pip3 install -r requirements.txt;apt install mono-devel -y"
    stdin, stdout, stderr = ssh.exec_command(octopus_install_command)
    results = stdout.readlines()
    print("[+] Octopus deployed successfully on %s " % name)

    #except:
    #    print("[-] Unable to deploy Octopus")

# login to the 2nd (redirector) and setup the apache

def setup_redirector(ip, name):
    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username='root', key_filename='private.key')
        octopus_install_command = "apt update; apt install certbot -y; apt install apache2 -y;apt-get install python-certbot-apache -y ; certbot --register-unsafely-without-email -m certficate@security.com -d myc2redirector.live --agree-tos;sudo a2enmod proxy_http"
        stdin, stdout, stderr = ssh.exec_command(octopus_install_command)
        results = stdout.readlines()
        print("[+] Apache and certficate installed on %s " % name)
    except:
        print("[-] Unable to setup the redirector")


if create_ssh_key():
    create_instances()
