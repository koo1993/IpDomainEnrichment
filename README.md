
# IpDomainEnrichment
Enrichment module for Ip and domains



# Usage
python3 \<path to python file\> -i \<path to domains/ips file\>
Tested and developed on Ubuntu 18.04.2 LTS

## enrichmentURLhaus.py
Bulk api pull from https://urlhaus.abuse.ch/ 

**limitation**
1. Incomplete data pull from haus api
    1. The api only provides 100 urls eventhough there are more than 100 urls that are reported from the lookup.
2. Only shows url that are online, offline are ignored. 
3. API only return the information for the domain and does not look at subdomain with the domain.
    1. Example: google.com host lookup does not look into drive.google.com. 

### Data column
| domain_or_ip | source (Data source from) | first_seen | url_count (how many url from this host are reported malicious) | surbl (is in surbl blacklist) | spamhaus_dbl | url | status (online/offline) | tags (if offline, display all the unique tags) |
|--------------|---------------------------------|------------|----------------------------------------------------------------|-------------------------------|--------------------|-----|-------------------------|------------------------------------------------|



## enrichmentFeodoTracker.py
Look up data from https://feodotracker.abuse.ch/
1. Data set used is only from recommended ip block list, which contains only active botnet c2 server or have beeen active in the past hours
2. lower false positive

### Data column
| domain_or_ip | source (Data source from) | port | status | hostname | as_number | as_name | country | first_seen | last_seen | malware |
|--------------|---------------------------|------|--------|----------|-----------|---------|---------|------------|-----------|---------|


## enrichmentVirusTotal.py
Look up data from [VirusTotal](https://www.virustotal.com/)
1. Using virustotal web key instead of using API key, non-official way to fetch data from virus total.
2. Only the scoring are extracted from the request. Able to include more information like: tags, country, as_owner (json data can be viewed here: https://pastebin.com/G9X8UN5c)

**\*Doing bulk enrichmentVirusTotal may result in your ip being rate limited**

### Data column
| domain_or_ip | source (Data source from) | malicious (how many vendors from virustotal are marked as malicious) | suspicious | harmless | undetected_timeout |
|--------------|---------------------------|----------------------------------------------------------------------|------------|----------|--------------------|


## scriptIntegrationCheck.py
A script that runs all enrichment scripts and creates a hitList.csv that register which enrichment script has a hit.
