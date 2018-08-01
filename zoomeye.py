#!/usr/bin/env python
#
# Simple ZoomEye CLI
# -- gelim

from ansicolor import green,red,yellow,cyan
from pprint import pprint
import argparse
import requests
import urllib3
import logging
import pickle
import json
import sys
import re
import os

urllib3.disable_warnings()

headers = {"Content-Type": "application/json"}
api={"login": "https://api.zoomeye.org/user/login",
     "search": "https://api.zoomeye.org/host/search",
     "info": "https://api.zoomeye.org/resources-info",
}
creds = {}

zoom_facets= ['country', 'os', 'product', 'service', 'port', 'device']

def zoom_get_config(args):
    conf_file = "%s/.zoomeye.p" % os.environ.get('HOME')
    api = dict()
    # command-line API key get precedence over other methods
    if args.user and args.password:
        creds['user'] = args.user
        creds['password'] = args.password
        pickle.dump(creds, open(conf_file, "wb")) # save to file
        return creds
    # if conf file exists, load it
    if os.path.isfile(conf_file):
        try:
            creds = pickle.load(open(conf_file, "r"))
        except:
            logging.error("Pickle file corrupted.")
            exit(-1)
        if not creds.get('user') or not creds.get('password'):
            logging.error("Pickle file structure mismatch.")
            exit(-2)
        return creds

def zoom_get_token(creds):
    data = {"username": creds['user'], "password": creds['password']}
    res = requests.post(api["login"], data=json.dumps(data),
                        headers=headers)
    if res.status_code != 200:
        logging.error("HTTP request error (%d)" % res.status_code)
        exit(-1)
    return json.loads(res.text)["access_token"]

def zoom_search(token, search, page, facets):
    params = {"query": search, "page": page, "facets": facets}
    headers["Authorization"] = "JWT %s" % token
    res = requests.get(api["search"], params=params, headers=headers, )
    if res.status_code != 200:
        logging.error("HTTP request error (%d)" % res.status_code)
        exit(-2)
    if facets:
        return json.loads(res.text)["facets"]
    else: return json.loads(res.text)

def zoom_info(token):
    headers["Authorization"] = "JWT %s" % token
    res = requests.get(api["info"], headers=headers)
    return json.loads(res.text)
    
def zoom_print_facets(result):
    facets_k = result.keys()
    if not facets_k: return
    count = str(result['device'][0]['count'])
    facets_k.remove("device")
    print "Total: %s" % red(count, bold=True)
    for k in facets_k:
        print "- %s" % green(k, bold=True)
        for e in result[k]:
            count = str(e['count'])
            name = e['name']
            if isinstance(name, int): name = str(name)
            print count.ljust(9) + cyan(name).ljust(20)
        print
    return

def shorten(s, l):
    if len(s) >= l:
        s = s[:l-5] + "[...]"
    return s

def print_results(search):
    for s in search:
        if args.debug:
            pprint(s)
        else:
            banner = s['portinfo'].get('banner', 'N/A')
            location = "N/A"
            title="N/A"
            http_status="N/A"
            if banner and re.match('^HTTP.*', banner):
                match=re.match('''^HTTP/1.\d (.*?)\r\n''', banner)
                if match: http_status = match.groups()[0].encode('ascii', 'ignore')
                match=re.match('''.*Location: (.*?)\r\n''', banner, re.DOTALL|re.IGNORECASE)
                if match: location =  match.groups()[0].encode('ascii', 'ignore')
                match=re.match('''.*<title>(.*?)</title>''', banner, re.DOTALL|re.IGNORECASE)
                if match: title =  match.groups()[0].encode('ascii', 'ignore')
            geoinfo = s['geoinfo']
            if not geoinfo:
                city_name = "N/A"
                country_code = "??"
                asn = "N/A"
            else:
                city_name = geoinfo['city']['names'].get('en', 'N/A')
                country_code = geoinfo['country'].get('code', '??')
                asn = str(geoinfo['asn'])
            dns = s.get('rdns', 'N/A').encode('ascii', 'ignore')
            port = str(s['portinfo']['port'])
            app = shorten(s['portinfo']['app'], 25)
            version = shorten(s['portinfo']['version'], 12)
            city_name = shorten(city_name, 10).encode('ascii', 'ignore')
            http_status = shorten(http_status, 20)
            if not country_code: country_code = '??'
            print s['ip'].ljust(16) + port.ljust(6) + \
                app.ljust(25) + \
                version.ljust(13) + \
                asn.ljust(7) + \
                country_code.ljust(3) + "/ " + \
                city_name.ljust(11) + \
                http_status.ljust(21) + \
                shorten(title, 30).ljust(30) + \
                "->" + location.ljust(40) + " " + dns

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO) # logging.DEBUG
    parser = argparse.ArgumentParser(description='Simple ZoomEye CLI')
    parser.add_argument("search", nargs='?', help="Your ZoomEye Search")
    parser.add_argument("--user", help="ZoomEye API user", default=None)
    parser.add_argument("--password", help="ZoomEye API password", default=None)
    parser.add_argument("-l", "--limit", help="Limit number of results printed (default: 20)", type=int, default=19)
    parser.add_argument("-f", "--facets", help="Facets to show (country,city,os,app,service,port,device)", default=None)
    parser.add_argument("-i", "--info", help="Show account info", action="store_true")
    parser.add_argument("-d", "--debug", help="Dump JSON detailed info for each result", action="store_true")
    parser.add_argument("--count", help="Only display number of results (default: False)", action="store_true")
    args = parser.parse_args()
    if args.facets == 'list':
        print ','.join(zoom_facets)
        exit(0)
    if not args.info and not args.search:
        print "You need to indicate a search query like 'app:SAP +country:RU'"
        exit(0)

    creds = zoom_get_config(args)
    token = zoom_get_token(creds)
    logging.debug("Token: %s" % token)
    if args.info:
        pprint(zoom_info(token))
        exit(0)
    if args.facets: facets=args.facets + ",device"
    else: facets=args.facets
    
    current_page = 1

    search = zoom_search(token, args.search, current_page, facets)
    current_page += 1
    if facets:
        zoom_print_facets(search)
        exit(0)
    else: sys.stderr.write("Number of results: %s\n" % search["total"])
    if args.count or search["total"] == 0: exit(0)
    if args.limit < 20: matches = search["matches"][:args.limit]
    else: matches = search["matches"]
    print_results(matches)

    # we asked for more pages?
    pages_asked = args.limit / 20 + 1

    while current_page <= pages_asked:
        res = zoom_search(token, args.search, current_page, facets)
        matches = res["matches"]
        if facets:
            zoom_print_facets(search)
            exit(0)
        reminder = (args.limit - (current_page-1)*20)
        if 0 <= reminder < 20: print_results(matches[:reminder])
        else: print_results(matches)
        current_page += 1
        
