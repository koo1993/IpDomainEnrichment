#!/usr/bin/env python3
import subprocess, os.path, re, csv
from argparse import ArgumentParser

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

# print("#### Generating all enrichment CSV file ####")

# print("\n### creating csv file from enrichmentURLhaus.py ###")
# subprocess.call(["./enrichmentURLhaus.py", "-i", args.filename])

# print("\n### creating csv file from enrichmentFeodoTracker.py ###")
# subprocess.call(["./enrichmentFeodoTracker.py", "-i", args.filename])

# print("\n### creating csv file from enrichmentVirusTotal.py ###")
# subprocess.call(["./enrichmentVirusTotal.py", "-i", args.filename])


#format filecontent and split
f = open (args.filename, "r")
allFileContent = f.read()
f.close()
allFileContent = allFileContent.replace(" ", "")
splitContent = re.split (",|\n", allFileContent)
temptSplitContent = []

trackerDict = {}

with open('./enrichedVirusTotal.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    print(reader)
    for row in reader:
        print(row)