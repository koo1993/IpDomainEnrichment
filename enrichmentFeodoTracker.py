#!/usr/bin/env python
#python3.9 


## https://feodotracker.abuse.ch/
# data set used is only from recommended ip block list, which contains only active botnet c2 server
# or have beeen active in the past hours
# lower false positive


from argparse import ArgumentParser
import os.path, re, csv, sys, requests, json, urllib3

def isValidFileForPaser(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg

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


# start of python logic / main
parser = ArgumentParser(description="Enrich IP or domain/host from feodotracker from its ipblocklist_recommended json")
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


response = requests.get('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json')
jsonResponse = json.loads(response.text)

ipMapping = {}
hostMapping = {}


index = 0 
for eachData in jsonResponse:
    if(eachData["ip_address"] in ipMapping):
        ipMapping[eachData["ip_address"]].append(index)
        # print("duplicated found ipMapping: " + eachData["ip_address"])
    else:
        ipMapping[eachData["ip_address"]] = [index]
    
    if(eachData["hostname"]  in hostMapping):
        hostMapping[eachData["hostname"]].append(index)
        print("duplicated found hostMapping: " + str(eachData["hostname"]))
    else:
        hostMapping[eachData["hostname"]] = [index]
    index += 1

# print (ipMapping)
# print (hostMapping)

#set up csv file
header = ["Domain Or Ip", "Port", "status", "hostname" , "as_number", "as_name", "country", "first_seen", "last_seen", "malware"]
f = open('enrichedFeodoTracker.csv', 'w', encoding='UTF8')
writer = csv.writer(f)
writer.writerow(header)

# doing enrichment for each entry
for eachEntry in splitContent:
    # For IP
    if(isIp(eachEntry)):
        #header = ["Domain Or Ip", "Port", "status", "hostname" , "as_number", "as_name", "country", "first_seen", "last_seen", "malware"]
        mainRow = [eachEntry]

        if eachEntry in ipMapping:
            print(f"[+] found: {eachEntry}")
            for eachIndex in ipMapping[eachEntry]:
                mainRowtoAppend = mainRow[:]
                mainRowtoAppend.append( jsonResponse[eachIndex]["port"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["status"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["hostname"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["as_number"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["as_name"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["country"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["first_seen"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["last_online"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["malware"] )
                writer.writerow(mainRowtoAppend)

        else:
            print(f"[-] Not found: {eachEntry}")
   
    #for domains
    elif(isDomain(eachEntry)):
        #header = ["Domain Or Ip", "Port", "status", "hostname" , "as_number", "as_name", "country", "first_seen", "last_seen", "malware"]
        mainRow = [eachEntry]
        
        if eachEntry in hostMapping:
            print(f"[+] found: {eachEntry}")
            for eachIndex in hostMapping[eachEntry]:
                mainRowtoAppend = mainRow[:]
                mainRowtoAppend.append( jsonResponse[eachIndex]["port"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["status"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["hostname"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["as_number"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["as_name"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["country"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["first_seen"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["last_online"] )
                mainRowtoAppend.append( jsonResponse[eachIndex]["malware"] )
                writer.writerow(mainRowtoAppend)

        else:
            print(f"[-] Not found: {eachEntry}")
   
    else:
        print("\"" + eachEntry + "\"" + " is not an ip or a domain")

print("Please check enrichedFeodoTracker.csv")