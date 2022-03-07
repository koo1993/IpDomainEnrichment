#!/usr/bin/env python
#python3.9 



# From virustotal website instead of using API, (possible unlimited lookup and for lookup only)
# non-official way to fetch data from virus total.
from argparse import ArgumentParser
import os.path, re, csv, requests, json


def isDomain(domainString):
    domainPattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    if(domainPattern.match(domainString)):
        return True
    else:
        return False

def isIp(ipString):
    ipPattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    )
    if(ipPattern.match(ipString)):
        return True
    else:
        return False

def isValidFileForPaser(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg



headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "X-Tool": "vt-ui-main",
    "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
}



# start of python logic / main
parser = ArgumentParser(description="Enrich IP or domain/host from VirusTotal")
parser.add_argument("-i", dest="filename", required=True,
                    help="input file with its content being domain or ip separated by , or newline", metavar="FilePath",
                    type=lambda x: isValidFileForPaser(parser, x))
args = parser.parse_args()

print("##### Still work in progress, able to scrap most of the content as per virus total search, but currently only shows how many vendor flag as malicious #### ")

#format filecontent and split
f = open (args.filename, "r")
allFileContent = f.read()
f.close()
allFileContent = allFileContent.replace(" ", "")
splitContent = re.split (",|\n", allFileContent)





# doing enrichment for each entry
for eachEntry in splitContent:
    # For IP
    if(isIp(eachEntry)):
        print("")
        url = "https://www.virustotal.com/ui/ip_addresses/" + eachEntry
        data = requests.get(url, headers=headers).json()
        print(eachEntry + " malicious: " + str(data["data"]["attributes"]["last_analysis_stats"]["malicious"]))
        print(f"[+] found: {eachEntry}")


    #for domains
    elif(isDomain(eachEntry)):   
        print("")
        url = "https://www.virustotal.com/ui/domains/" + eachEntry
        data = requests.get(url, headers=headers).json()
        print(eachEntry + " malicious: " + str(data["data"]["attributes"]["last_analysis_stats"]["malicious"]))
        print(f"[+] found: {eachEntry}")


    else:
        print("\"" + eachEntry + "\"" + " is not an ip or a domain")


