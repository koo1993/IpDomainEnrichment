#!/usr/bin/env python3
import subprocess, os.path, re, csv
from argparse import ArgumentParser
#import pandas as pd
##require pip3 install pandas

def isValidFileForPaser(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg



# start of python logic / main
parser = ArgumentParser(description="Automate all enrichment script and filter out those domain/ip that is flagged by any of the enrichment")
parser.add_argument("-i", dest="filename", required=True,
                    help="input file with its content being domain or ip separated by , or newline", metavar="FilePath",
                    type=lambda x: isValidFileForPaser(parser, x))
args = parser.parse_args()

print("#### Generating all enrichment CSV file ####")

print("\n### creating csv file from enrichmentURLhaus.py ###")
subprocess.call(["./enrichmentURLhaus.py", "-i", args.filename])

print("\n### creating csv file from enrichmentFeodoTracker.py ###")
subprocess.call(["./enrichmentFeodoTracker.py", "-i", args.filename])

print("\n### creating csv file from enrichmentVirusTotal.py ###")
subprocess.call(["./enrichmentVirusTotal.py", "-i", args.filename])


#format filecontent and split
f = open (args.filename, "r")
allFileContent = f.read()
f.close()
allFileContent = allFileContent.replace(" ", "")
splitContent = re.split (",|\n", allFileContent)

fileNamePath = 'hitList.csv'

urlhausList = []
feodoTrackerList = []
virusTotalList = []

with open("./enrichedURLhaus.csv", 'r') as readObj:
    csvReader = csv.reader(readObj)
    header = next(csvReader)

    if header != None:
        for row in csvReader:
            if row[0] not in urlhausList:
                urlhausList.append(row[0].replace("www.", ""))

with open("./enrichedFeodoTracker.csv", 'r') as readObj:
    csvReader = csv.reader(readObj)
    header = next(csvReader)

    if header != None:
        for row in csvReader:
            if row[0] not in feodoTrackerList:
                feodoTrackerList.append(row[0])

with open("./enrichedVirusTotal.csv", 'r') as readObj:
    csvReader = csv.reader(readObj)
    header = next(csvReader)

    if header != None:
        for row in csvReader:
            if(int(row[2]) > 0 or int(row[3]) > 0):
                virusTotalList.append(row[0])


header = ["domain_or_ip", "urlhause", "feodotracker", "virustotal"]
f = open(fileNamePath, 'w', encoding='UTF8')
writer = csv.writer(f)
writer.writerow(header)

for eachData in splitContent:

    row = []
    row.append(eachData)

    if eachData in urlhausList:
        row.append(1)
    else:
        row.append(0)
    
    if eachData in feodoTrackerList:
        row.append(1)
    else:
        row.append(0)
    
    if eachData in virusTotalList:
        row.append(1)
    else:
        row.append(0)

    writer.writerow(row)

print(f"Please check {fileNamePath}")