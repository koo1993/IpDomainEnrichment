#!/usr/bin/env python3
import subprocess, os.path, re, csv
from argparse import ArgumentParser
import pandas as pd
#require pip3 install pandas

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


# #format filecontent and split
# f = open (args.filename, "r")
# allFileContent = f.read()
# f.close()
# allFileContent = allFileContent.replace(" ", "")
# splitContent = re.split (",|\n", allFileContent)
# temptSplitContent = []

trackerDict = {}

# Read the files into two dataframes.
df1 = pd.read_csv('./enrichedVirusTotal.csv')
df2 = pd.read_csv('./enrichedURLhaus.csv')
df3 = pd.read_csv('./enrichedFeodoTracker.csv')

# Merge the two dataframes, using _ID column as key
df4 = pd.merge(df1, df2, on = 'domain or ip', how = "outer")
df4.set_index('domain or ip', inplace = True)

# Merge the two dataframes, using _ID column as key
df5 = pd.merge(df4, df3, on = 'domain or ip', how = "outer")
df5.set_index('domain or ip', inplace = True)

# Write it to a new CSV file
df5.to_csv('CSV3.csv')


# process Virustotal csv first
# print("### processing ./enrichedVirusTotal.csv ###")
# with open('./enrichedVirusTotal.csv', newline='') as csvfile:
#     reader = csv.DictReader(csvfile)
#     for row in reader:
#         # print(row)
#         if(int(row["malicious"]) > 0 or int(row["suspicious"]) > 0):
#             trackerDict[row["domain or ip"]] = {}
#             trackerDict[row["domain or ip"]]["source"] = row["source"] 
#             trackerDict[row["domain or ip"]]["malicious"] = row["malicious"] 
#             trackerDict[row["domain or ip"]]["suspicious"] = row["suspicious"]

# print("### processing ./enrichedURLhaus.csv###")
# with open('./enrichedURLhaus.csv', newline='') as csvfile:
#     reader = csv.DictReader(csvfile)
#     for row in reader:
#         print(row)