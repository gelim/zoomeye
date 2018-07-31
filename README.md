ZoomEye API simple CLI client
----------------------------

Script that allows to query the ZoomeEye giant scan database.

Main features:

- basic search that returns list of matching IP, search format is like
  `key1:value1 +key2:value2`. Keys are stuffed indexed by ZoomeEye
  like app, port, country. You can search with pure IP, or subnets
  like `1.2.3.0/24` as well.

- facets that gives "top-10" statistics for several hardcoded
  perpsectives (app, country, port, ...)


# Usage

```
usage: zoomeye.py [-h] [--user USER] [--password PASSWORD] [-l LIMIT]
                  [-f FACETS] [-i] [--port] [--short] [--count]
                  search

Simple ZoomEye CLI

positional arguments:
  search                Your ZoomEye Search

optional arguments:
  -h, --help            show this help message and exit
  --user USER           ZoomEye API user
  --password PASSWORD   ZoomEye API password
  -l LIMIT, --limit LIMIT
                        Limit number of results printed (default: 20)
  -f FACETS, --facets FACETS
                        Facets to show (country,os,app,service,port,device)
  -i, --info            Show account info
  --port                Show port with IP (default: False)
  --short               Shows only the IP as results
  --count               Only display number of results (default: False)

```


First time you indicate `--user` and `--password` it will save it in
the user's home so next time you run the script it will use those
stored values instead.
