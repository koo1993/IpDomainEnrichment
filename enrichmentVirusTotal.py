#!/usr/bin/env python3
#python3.9 


from argparse import ArgumentParser
import os.path, re, csv, requests, json, urllib3, time

def listToStringWithComma(listOfString):
    return ", ".join([str(item) for item in listOfString])


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
parser.add_argument("-o", dest="ofilename", required=False,
                    help="Output file path and name", metavar="FilePath")
args = parser.parse_args()


#format filecontent and split
f = open (args.filename, "r")
allFileContent = f.read()
f.close()
allFileContent = allFileContent.replace(" ", "")
splitContent = re.split (",|\n", allFileContent)

fileNamePath = 'enrichedVirusTotal.csv'

if(args.ofilename):
    fileNamePath = args.ofilename

#set up csv file
header = ["domain_or_ip", "source", "malicious", "suspicious", "harmless", "undetected_timeout"]
f = open(fileNamePath, 'w', encoding='UTF8')
writer = csv.writer(f)
writer.writerow(header)


# doing enrichment for each entry
for eachEntry in splitContent:
    # For IP
    if(isIp(eachEntry)):
        

        url = "https://www.virustotal.com/ui/ip_addresses/" + eachEntry
        response = requests.get(url, headers=headers)

        if(response.status_code == 200):
            data = response.json()
        
            if( int(data["data"]["attributes"]["last_analysis_stats"]["malicious"]) > 0 or int(data["data"]["attributes"]["last_analysis_stats"]["suspicious"]) >0 ):
                mainRow = [eachEntry, "virustotal"] 
                # header = ["domain or ip"", "source", "malicious", "suspicious", "harmless", "undetected/timeout"]
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["malicious"] )
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["suspicious"] )
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["harmless"] )
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["undetected"] + data["data"]["attributes"]["last_analysis_stats"]["timeout"] )
                writer.writerow(mainRow)
                print(f"[+] found: {eachEntry} suspicious/malicious")
            else:
                print(f"[+] found: {eachEntry} benign")
            
        else: 
            print("***Virus total do not have the information for " + eachEntry)
            print("***please rerun virusTotalEnrichment.py again after 2mins for virustotal to update")
        print("sleep for 3 sec")
        time.sleep(3)

    #for domains
    elif(isDomain(eachEntry)):   
  
        url = "https://www.virustotal.com/ui/domains/" + eachEntry
        response = requests.get(url, headers=headers)
        
        if(response.status_code == 200):
            data = response.json()
            if( int(data["data"]["attributes"]["last_analysis_stats"]["malicious"]) > 0 or int(data["data"]["attributes"]["last_analysis_stats"]["suspicious"]) >0 ):
                mainRow = [eachEntry, "virustotal"] 
                # header = ["domain or ip"", "source", "malicious", "suspicious", "harmless", "undetected/timeout"]
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["malicious"] )
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["suspicious"] )
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["harmless"] )
                mainRow.append( data["data"]["attributes"]["last_analysis_stats"]["undetected"] + data["data"]["attributes"]["last_analysis_stats"]["timeout"] )
                writer.writerow(mainRow)
                print(f"[+] found: {eachEntry} suspicious/malicious")
            else:
                print(f"[+] found: {eachEntry} benign")
       
        else: 
            print("***Virus total do not have the information for " + eachEntry)
            print("***please rerun virusTotalEnrichment.py again after 2mins for virustotal to update")
        print("sleep for 3 sec")
        time.sleep(3)

    else:
        print("\"" + eachEntry + "\"" + " is not an ip or a domain")


print(f"Please check {fileNamePath}")