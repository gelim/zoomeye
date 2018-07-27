#!/usr/bin/env python
import sys
import json
import requests
import argparse

######## CHANGE THESE  (Or use `--email` and `--password` arguments) #########
USER_EMAIL = "xxx"
USER_PASSWORD = "xxx"
##############################################################################

parser = argparse.ArgumentParser(
    description='Simple ZoomEye searcher, outputs IPs to stdout or file')

parser.add_argument("search", help="Your ZoomEye Search")
parser.add_argument(
    "-p", "--pages", help="Number of pages to search (Default: 1)", type=int, default=5)
parser.add_argument("--email", help="Your ZoomEye email", default=USER_EMAIL)
parser.add_argument(
    "--password", help="Your ZoomEye password", default=USER_PASSWORD)
parser.add_argument(
    "-s", "--save", help="Save output to results.txt", action="store_true")
parser.add_argument("-pl", "--platform",
                    help="Platforms to search, accepts \"host\" and \"web\" (Default: host)", default="host")
parser.add_argument("--port", help="Include the port number in the results (e.g., 127.0.0.1:1337) (Only for host platform)", action="store_true")
parser.add_argument("--short", help="Shows only the IP as results", action="store_true")
parser.add_argument("--domain", help="Output the site address rather than the IP. (Only for web platform)", action="store_true")
args = parser.parse_args()

QUERY = args.search
PAGECOUNT = args.pages
EMAIL = args.email
PASSWORD = args.password

SEARCH_TYPE = args.platform


API_URL = "https://api.zoomeye.org"  # In case the ZoomEye API URL ever changes

USER_DATA = '{"username": ' + '"' + EMAIL + '"' + \
    ', "password":  ' + '"' + PASSWORD + '"' + '}'
AUTH_REQUEST = requests.post(API_URL + '/user/login', data=USER_DATA)

# Attempts to access the raw token, if there is a KeyError it means the credentials are incorrect


def getToken():
    try:
        ACCESS_TOKEN = AUTH_REQUEST.json()['access_token']
        return ACCESS_TOKEN
    except KeyError:
        print("[ERROR] Invalid Credentials, please specify an email and password either in this file or with `--email` and `--password` arguments")
        quit()

def detectSaveMode():
    if args.save:
        print("You have enabled save. All IPs will be saved to results.txt")
        try:
            global resultsFile
            resultsFile = open('results.txt', 'w')
        except:
            print(
                "[ERROR] Could not write to results.txt, please check your permissions")
            quit()

# Loopy loop
def getResult():
    # This is the prefixed Token
    TOKEN = "JWT " + getToken()
    # Add the prefixed token to the headers
    HEADERS = {"Authorization": TOKEN}

    currentPage = 1
    while currentPage <= PAGECOUNT:
        if args.save:
            print("\nPage " + str(currentPage))

        SEARCH = requests.get(API_URL + '/' + SEARCH_TYPE + '/search',
                              headers=HEADERS, params={"query": QUERY, "page": currentPage})
        response = json.loads(SEARCH.text)
        if not response: quit() # no more results?

        for m in response["matches"]:
            if SEARCH_TYPE == "host":
                if args.port:
                    resultItem = m["ip"] + ":" + str(m["portinfo"]["port"])
                else:
                    resultItem = m["ip"]
                if not args.short:
                    resultItem += "\tAS:%s (%s)\tLoc:%s /%s" % (m['geoinfo']['asn'], m['geoinfo']['aso'],
                                                            m['geoinfo']['country']['code'],
                                                            m['geoinfo']['country']['names']['en'])

                if args.save:
                    resultsFile.write(resultItem + "\n")
                print(resultItem)

            if SEARCH_TYPE == "web":
                if args.domain:
                    resultItem = m["site"]
                else:
                    resultItem = m["ip"][0]
                if args.save:
                    resultsFile.write(resultItem + "\n")
                print(resultItem)
            ipCount()
        currentPage += 1


def ipCount():
    if args.save:
        resultsFile.close()  # Close as write
        ip_count = sum(1 for line in open("results.txt", "r"))  # Open as read
        print("\n" + str(ip_count) + " IPs saved to results.txt")


detectSaveMode()
getResult()
ipCount()
