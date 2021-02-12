#!/usr/bin/env python
"""
Code for deleting unused SSL CERTS/KEYS on A10 Load Balancer
"""
import getpass
import pexpect
import sys
import os

USER = "dnoland"
PASSWORD = getpass.getpass()
DELETE_KEY = "slb ssl-delete private-key"
DELETE_CRT = "slb ssl-delete certificate"

F = open('hosts', 'r')

with open('hosts') as F:
    HOSTS = [line.strip('\n') for line in F]

for host in HOSTS:

    VERBOSE = 0
    COUNT = 0
    CERT = []
    MYSTRING = None

    try:
        try:

            CHILD = pexpect.spawn('ssh -o "StrictHostKeyChecking no"'
                                  + " " '%s@%s' % (USER, host))

            CHILD.logfile = open('/Users/dnoland/Desktop/mylog', 'a')
            if VERBOSE:
                CHILD.logfile = sys.stdout
            CHILD.timeout = 10
            CHILD.expect('Password:')
        except pexpect.TIMEOUT:
            raise Exception("Couldn't log on to the switch")
        CHILD.sendline(PASSWORD)
        CHILD.expect('>')
        CHILD.sendline('en')
        CHILD.expect('Password:')
        CHILD.sendline('\n')
        CHILD.expect('#')
        CHILD.sendline('show slb ssl CERT sort-by name | i Unbound')
        CHILD.expect('Unbound')
        CHILD.expect(host)
        MYSTRING = CHILD.before
        print MYSTRING
        MYSTRING = os.linesep.join([s for s in MYSTRING.splitlines() if s])
        if "Unbound" in MYSTRING:
            print host + '\n' + MYSTRING
            MYLIST = MYSTRING.splitlines()
            for item in MYLIST:
                CERT.append(item.split(" "))
            CHILD.sendline('conf t')
            CHILD.expect('\(config\)#')
            CHILD.sendline('terminal length 0')
            CHILD.expect('\(config\)#')
            for item in CERT:
                if CERT[COUNT][4] == 'key':
                    CHILD.sendline(DELETE_KEY + " " + item[1])
                    COUNT += 1
                elif CERT[COUNT][4] == 'certificate':
                    CHILD.sendline(DELETE_CRT + " " + item[1])
                    COUNT += 1
                elif CERT[COUNT][4] == 'certificate/key':
                    CHILD.sendline(DELETE_CRT + " " + item[1])
                    CHILD.sendline(DELETE_KEY + " " + item[1])
                    COUNT += 1
            CHILD.sendline('show slb ssl CERT sort-by name')
            CHILD.expect('name')
            CHILD.expect(host)
            print host + CHILD.before
            CHILD.expect('#')
            CHILD.sendline('wr me')
            CHILD.expect('\[OK\]')
            CHILD.sendline('exit')
        else:
            print host
            print "No Unbound CERT or KEYS found"
        CHILD.sendline('exit')
        CHILD.expect('>')
        CHILD.sendline('exit')
        CHILD.expect(':')
        CHILD.sendline('Y')
    except (pexpect.EOF, pexpect.TIMEOUT), error:
        error("Error finishing the work.")
        raise
