#python3.9 
#!/usr/bin/env python

#limitation 
# 1. incomplete data pull from haus api
#      the api only provides 100 urls eventhough there are more than 100 urls that are reported from the lookup.
# 2. only shows url that are online, offline are ignored. 
# 3. API only return the information for subdomain related to the domain.
#       Example: google.com host lookup does not look into drive.google.com. 

from argparse import ArgumentParser
import os.path, re, csv, sys, requests, json, urllib3

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


def queryDomainHaus(domain):
    # Construct the HTTP request
    data = {'host' : domain}
    response = pool.request_encode_body("POST", "/v1/host/", fields=data, encode_multipart=False)
    # Parse the response from the API
    response = response.data.decode("utf-8", "ignore")
    # Convert response to JSON
    json_response = json.loads(response)
    return json_response

def listToStringWithComma(listOfString):
    return ", ".join([str(item) for item in listOfString])

def dicKeyToStringWithComma(dicWithKey):
    return ", ".join([str(item) for item in dicWithKey])


# return true if tabulated with data , else false
# its a big functions that edits dicForAllTag to contains all the unique tags and write to CSV files
def loopThroughUrlsForOnline(dicForAllTags, urlsJson, mainRowFix):
    isOnlineSeen = False

    for url in urlsJson:
        mainRowAppend = mainRowFix[:]
        isTagNone = True if(url["tags"] is None) else False
        if(url["url_status"] == "online"):
            isOnlineSeen = True

            #header = [... "Url", "Online/Offline", "Tags"]
            mainRowAppend.append(url["url"])
            mainRowAppend.append("online")
            mainRowAppend.append(listToStringWithComma(url["tags"]))
            writer.writerow(mainRowAppend)


        
        if (not isTagNone):
            for tag in url["tags"]:
                dicForAllTags[tag] = 0
              

    return isOnlineSeen




# start of python logic / main
parser = ArgumentParser(description="Enrich IP or domain from URLhaus. currently, only online url will be fetched. A file called enriched.csv will be produced")
parser.add_argument("-i", dest="filename", required=True,
                    help="input file with its content being domain or ip separated by , or newline", metavar="FilePath",
                    type=lambda x: isValidFileForPaser(parser, x))
args = parser.parse_args()


#format filecontent and split
f = open (args.filename, "r")
allFileContent = f.read()
f.close()
allFileContent = allFileContent.replace(" ", "")
splitContent = re.split (",|\n", allFileContent)



#set up csv file
header = ["Domain Or Ip", "Source", "Firstseen Date", "Url Count (how many url from this host are reported malicious)", "SURBL blacklist", "spamhaus_dbl", "Url", "Online/Offline", "Tags (if offline, display all the unique tags)"]
f = open('enrichedURLhaus.csv', 'w', encoding='UTF8')
writer = csv.writer(f)
writer.writerow(header)


# Prepare HTTPSConnectionPool for faster bulk query
pool = urllib3.HTTPSConnectionPool('urlhaus-api.abuse.ch', port=443, maxsize=10)
urllib3.disable_warnings()

# doing enrichment for each entry
for eachEntry in splitContent:

    # For IP
    if(isIp(eachEntry)):
        jsonResponse = queryDomainHaus(eachEntry)

        if jsonResponse['query_status'] == 'ok':
            print(f"[+] FOUND:     {eachEntry}")
            #header = ["Domain Or Ip", "Source", "Firstseen Date", "Url Count", "SURBL blacklist", "spamhaus_dbl", "Url", "Online/Offline", "Tags"]
            mainRow = [eachEntry, "urlhaus.abuse.ch", jsonResponse["firstseen"], jsonResponse["url_count"] ,jsonResponse["blacklists"]["surbl"], jsonResponse["blacklists"]["spamhaus_dbl"]]
            dicForTags = {}
     
            hasOnline = True
            hasOnline = loopThroughUrlsForOnline(dicForTags, jsonResponse["urls"], mainRow)

            if(not hasOnline):
                mainRow.append("-")
                mainRow.append("offline")
                mainRow.append(dicKeyToStringWithComma(dicForTags))
                writer.writerow(mainRow)

        elif jsonResponse['query_status'] == 'no_results':
            print(f"[-] Not found: {eachEntry}")
            continue
        else:
            print(f"[-] Error:     {eachEntry}")
            continue
    
    #for domains
    elif(isDomain(eachEntry)):
        jsonResponse = queryDomainHaus(eachEntry)
        if jsonResponse['query_status'] == 'ok':
            print(f"[+] FOUND:     {eachEntry}")
            #header = ["Domain Or Ip", "Source", "Firstseen Date", "Url Count", "SURBL blacklist", "spamhaus_dbl", "Url", "Online/Offline", "Tags"]
            mainRow = [eachEntry, "urlhaus.abuse.ch", jsonResponse["firstseen"], jsonResponse["url_count"] ,jsonResponse["blacklists"]["surbl"], jsonResponse["blacklists"]["spamhaus_dbl"]]
            dicForTags = {}
     
            hasOnline = True
            hasOnline = loopThroughUrlsForOnline(dicForTags, jsonResponse["urls"], mainRow)

            if(not hasOnline):
                mainRow.append("-")
                mainRow.append("offline")
                mainRow.append(dicKeyToStringWithComma(dicForTags))
                writer.writerow(mainRow)

        elif jsonResponse['query_status'] == 'no_results':
            print(f"[-] Not found: {eachEntry}")
            continue
        else:
            print(f"[-] Error:     {eachEntry}")
            continue

    else:
        print(eachEntry + " is not an ip or a domain")

print("Please check enrichedURLhaus.csv")