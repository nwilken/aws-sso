#!/usr/bin/env python

import sys
import boto.sts
import boto.s3
import requests
import getpass
import ConfigParser
import base64
import logging
import xml.etree.ElementTree as ET
import re
import json
import time
try:
    import httplib
except ImportError:
    import http.client as httplibfrom
from bs4 import BeautifulSoup
from os.path import expanduser, isfile
from urlparse import urlparse, urlunparse
import pickle

##########################################################################
# Variables

# region: The default AWS region that this script will connect
# to for all API calls
region = 'us-west-2'

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should only be used for dev/test
sslverification = True

# Where to store session cookies for future logins
cookiefile = expanduser('~/.aws/sso_session_cookies')

# idpentryurl: The initial url that starts the authentication process.
idpentryurl = 'https://shibboleth2.asu.edu/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices'
duourl = "https://weblogin.asu.edu/cas/login?service=https%3A%2F%2Fshibboleth2.asu.edu%2Fidp%2FAuthn%2FExternal%3Fconversation%3De1s1&entityId=urn%3Aamazon%3Awebservices"


# Uncomment to enable low level debugging
#httplib.HTTPConnection.debuglevel = 9
#logging.basicConfig()
#logging.getLogger().setLevel(logging.DEBUG)
#requests_log = logging.getLogger("requests.packages.urllib3")
#requests_log.setLevel(logging.DEBUG)
#requests_log.propagate = True

##########################################################################

# Initiate session handler
session = requests.Session()

# If there is no cached login, or it's expired, go through the login process again
need_login = True
assertion = ''

if isfile(cookiefile):
    with open(cookiefile, 'rb') as f:
        session.cookies.update(pickle.load(f))
    response = session.post(idpentryurl, data={}, verify=sslverification)
    # print response.text
    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text.decode('utf8'), 'lxml')
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            #print(inputtag.get('value'))
            assertion = inputtag.get('value')
    if (assertion != ''):
        need_login = False

if need_login:
    # Get the federated credentials from the user
    if len(sys.argv) > 4:
        username = sys.argv[1]
        password = sys.argv[2]
        duration = sys.argv[3]
        organization = sys.argv[4]
    else:
        print "ASURITE Username:",
        username = raw_input()
        password = getpass.getpass()
        print ''
        duration = 30
        organization = 'production'

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    formresponse = session.get(idpentryurl, verify=sslverification)
    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = formresponse.url

    # Parse the response and extract all the necessary values
    # in order to build a dictionary of all of the form values the IdP expects
    formsoup = BeautifulSoup(formresponse.text.decode('utf8'), 'lxml')
    payload = {}

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        #print "name=%s, value=%s" %(name,value)
        if "user" in name.lower():
            #Make an educated guess that this is the right field for the username
            payload[name] = username
        elif "email" in name.lower():
            #Some IdPs also label the username field as 'email'
            payload[name] = username
        elif "pass" in name.lower():
            #Make an educated guess that this is the right field for the password
            payload[name] = password
        elif "auth" in name.lower():
            #print "Setting AuthState to %s" %value
            payload['AuthState'] = value
        else:
            #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
            payload[name] = value

    #payload['_eventId_proceed'] = ''

    # Populate the following from input or defaults 
    payload['session-duration'] = duration
    payload['organization'] = organization

    # Debug the parameter payload if needed
    # Use with caution since this will print sensitive output to the screen
    #print payload

    # Some IdPs don't explicitly set a form action, but if one is set we should
    # build the idpauthformsubmiturl by combining the scheme and hostname 
    # from the entry url with the form action target
    # If the action tag doesn't exist, we just stick with the 
    # idpauthformsubmiturl above
    #for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
    #    action = inputtag.get('action')
    #    print (action)
    #    if action:
    #        parsedurl = urlparse(idpentryurl)
    #        if "?" !=  action.lower():
    #            idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action
    #        else:
    #            # empty action so will use the hardcoded login URL
    #            idpauthformsubmiturl = loginurl


    # Performs the submission of the IdP login form with the above post data

    #print "=====Posting URL: %s" %( idpauthformsubmiturl)
    response = session.post(
        idpauthformsubmiturl, 
        data=payload, verify=sslverification)

    # Store the final URL to use after successful authentication with DUO
    parenturl=response.url

    # Overwrite and delete the credential variables, just for safety
    username = '##############################################'
    password = '##############################################'
    del username
    del password


    # Debug the response if needed
    #print (response.text)

    print "Logging you in..."

    # Decode the response and extract the iframe info to authenticate with Duo
    soup = BeautifulSoup(response.text.decode('utf8'), 'lxml')
    datahost = ''
    datasigrequest = ''
    sigresponse = ''

    # print (soup.prettify())
    for iframetag in soup.find_all("iframe", id="duo_iframe"):
        # print "iframetag=%s" % iframetag
        datahost = iframetag['data-host']
        u = iframetag['data-sig-request']
        #Exctract only the TX portion
        i = u.find(':APP')
        datasigrequest = u[0:i]
        sigresponseappstr = u[i:len(u)]
        #print "datahost=%s, sigresponseappstr=%s, datasigrequesigresponseappstr=%s" %(datahost,sigresponseappstr,datasigrequest)

    if datahost == '':
        print("Couldn't log you in. Check your username and password.")
        sys.exit(1)

    casexecution = soup.find("input", attrs={"name": "execution"})['value']

    # Create the Duo session
    duosession = requests.Session()

    # Opens the duo authentication url and follows all of the HTTP302 redirects, and
    # gets to the prompt
    urlpayload = {}
    urlpayload['tx'] = datasigrequest
    urlpayload['parent'] = parenturl
    duoauthurl = "https://" + datahost + "/frame/web/v1/auth" 
    #print "===== duoauthurl=%s" %duoauthurl
    response = duosession.get(duoauthurl, params=urlpayload, verify=sslverification)
    #print (response.text)

    urlpayload['StateId'] = idpauthformsubmiturl
    response = duosession.post(duoauthurl, data=urlpayload, verify=sslverification)
    #print (response.text)
    duourlpromt = response.url

    #for some reason we need to GET and POST to Duo's prompt URL
    formresponse = duosession.get(duourlpromt,  verify=sslverification)
    #print (formresponse.text)
    #print formresponse.url
    duourlprompt = formresponse.url

    formsoup = BeautifulSoup(formresponse.text.decode('utf8'), 'lxml')
    # Post duo prompt paramenters 
    payload = {}
    #store sid to use later when we query duo status after authentication push
    sid = ""

    for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
        # print inputtag
        name = inputtag.get('name','')
        value = inputtag.get('value','')
        # print "name=%s, value=%s" %(name,value)
        if "sid" in name.lower():
            payload[name] = value
            sid = value
        elif "preferred_device" in name.lower():
            payload['device'] = value
        elif "preferred_factor" in name.lower():
            #Make an educated guess that this is the right field for the password
            payload['factor'] = value
        elif "out_of_date" in name.lower():
            payload[name] = value

    print 'Enter an authentication factor ("push", "phone", "sms") or Duo passcode. Or press enter to use your default factor: ',
    auth_factor = raw_input()

    # Only throw up the "press enter after approving" prompt for phone and push flows, it's not needed for SMS or passcode
    wait_for_confirm = True

    if auth_factor == '':
        print('Using default auth factor (%s)' % payload['factor'])
    elif auth_factor == 'push':
        print('Sending a Duo Push to your phone.')
        if 'device' not in payload or payload['device'] == '':
            payload['device'] = 'phone1'
        payload['factor'] = 'Duo Push'
    elif auth_factor == 'phone':
        print('Calling you.')
        if 'device' not in payload or payload['device'] == '':
            payload['device'] = 'phone1'
        payload['factor'] = 'Phone Call'
    elif auth_factor == 'sms':
        payload['factor'] = 'sms'
        session.post(
            duourlprompt,
            data=payload, verify=sslverification)
        print 'Please enter the code we texted you:  ',
        passcode = raw_input()
        payload['factor'] = 'Passcode'
        payload['passcode'] = passcode
        wait_for_confirm = False
    else:
        print('Using passcode.')
        payload['factor'] = 'Passcode'
        payload['passcode'] = auth_factor
        wait_for_confirm = False

    response = session.post(
        duourlprompt,
        data=payload, verify=sslverification)

    duourlprompt = formresponse.url
    # print(duourlprompt)

    # Debug the response if needed
    # print (response.text)
    d = json.loads(response.text)
    payload = {}
    payload['txid'] = d["response"]["txid"]
    payload['sid'] = sid

    duourlstatus = "https://" + datahost + "/frame/status"

    if wait_for_confirm:
        print "Please press enter after you've accepted the Duo request",
        junkin = raw_input()

    response = session.post(
    duourlstatus,
    data=payload, verify=sslverification)
    # print (response.text)

    duourlstatus = response.url
    # print(duourlstatus)

    response = session.post(
    duourlstatus + '/' + payload['txid'],
    data=payload, verify=sslverification)
    # print (response.text)

    payload = {}
    d = json.loads(response.text)
    sig_response = d["response"]["cookie"] + sigresponseappstr
    payload["signedDuoResponse"] = sig_response
    payload["_eventId"] = "submit"
    payload["execution"] = casexecution
    parenturl = d["response"]["parent"]
    response = session.post(
    duourl, 
    data=payload, verify=sslverification)

    # print (response.text)


    # Decode the response and extract the SAML assertion
    soup = BeautifulSoup(response.text.decode('utf8'), 'lxml')
    # Look for the SAMLResponse attribute of the input tag (determined by
    # analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            #print(inputtag.get('value'))
            assertion = inputtag.get('value')

    # Better error handling is required for production use.
    if (assertion == ''):
        #TODO: Insert valid error checking/handling
        print 'Response did not contain a valid SAML assertion'
        sys.exit(0)

# Debug only
# print(base64.b64decode(assertion))

# Parse the returned assertion and extract the authorized roles
awsroles = []
#print base64.b64decode(assertion)
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
#    print saml2attribute
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)

# Note the format of the attribute value should be role_arn,principal_arn
# but lots of blogs list it as principal_arn,role_arn so let's reverse
# them if needed
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If I have more than one role, ask the user which one they want,
# otherwise just proceed
print ""
if len(awsroles) > 1:
    i = 0
    print "Please choose the role you would like to assume:"
    for awsrole in awsroles:
        print '[', i, ']: ', awsrole.split(',')[0]
        i += 1
    print "Selection: ",
    selectedroleindex = raw_input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print 'You selected an invalid role index, please try again'
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    try:
        role_arn = awsroles[0].split(',')[0]
    except IndexError:
        print "Could not find role ARN"
        sys.exit(0)
    principal_arn = awsroles[0].split(',')[1]

with open(cookiefile, 'wb') as f:
    pickle.dump(session.cookies, f)

# Use the assertion to get an AWS STS token using Assume Role with SAML
conn = boto.sts.connect_to_region(region)
token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

# Write the AWS STS token into the AWS credential file
home = expanduser("~")
filename = home + awsconfigfile

# Read in the existing config file
config = ConfigParser.RawConfigParser()
config.read(filename)

# Put the credentials into a saml specific section instead of clobbering
# the default credentials
if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)
config.set('saml', 'aws_access_key_id', token.credentials.access_key)
config.set('saml', 'aws_secret_access_key', token.credentials.secret_key)
config.set('saml', 'aws_session_token', token.credentials.session_token)

# Write the updated config file
with open(filename, 'w+') as configfile:
    config.write(configfile)

# Give the user some basic info as to what has just happened
print '\n\n----------------------------------------------------------------'
print 'Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(filename)
print 'Note that it will expire at {0}.'.format(token.credentials.expiration)
print 'After this time, you may safely rerun this script to refresh your access key pair.'
print 'To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile saml ec2 describe-instances).'
print '----------------------------------------------------------------\n\n'

# Use the AWS STS token to list all of the S3 buckets
s3conn = boto.s3.connect_to_region(region,
                     aws_access_key_id=token.credentials.access_key,
                     aws_secret_access_key=token.credentials.secret_key,
                     security_token=token.credentials.session_token)

buckets = s3conn.get_all_buckets()

print 'Simple API example listing all S3 buckets:'
print(buckets)

