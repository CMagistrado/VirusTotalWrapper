#!/usr/bin/env python3
#
# vt.py
# Handler for VirusTotal, given a free API.
#
# Bandwidth:
# Privileges	public key
# Request rate	4 requests/minute
# Daily quota	5760 requests/day
# Monthly quota	Uncapped requests/month
#
# Given the bandwidth, and the fact that one must request a url to be checked,
# and then request the results, the amount of urls classified per minute or day is n/2.
# We can receive 5760/2 or 2880 URLs per day. =]
#
# url: The URL that should be scanned. This parameter accepts a list of URLs 
# (up to 4 with the standard request rate) so as to perform a batch scanning request with one single call. The URLs must be separated by a new line character.

# https://stackoverflow.com/questions/22698244/how-to-merge-two-json-string-in-python
# Merge two json strings to one json
import requests, logging, time

class VirusTotal:

    def __init__(self):
        self.api = "06152a7ad29de8672ae94b27e7079f2911b0c64f9c63f4cb516113c9919420a1"
        self.av_list = open('VT-AVs', 'r').read().splitlines()
        logging.basicConfig(filename='vt.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
        return
    
    def inspect(self, input_filename, output_filename):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Gives url to 
        '''
        ifile = self.read(input_filename)
        ofile = self.append(output_filename)
        domainList = ifile.read().split()

        for i in range(0, len(domainList)):
            result = self.request(domainList[i])
            ofile.write(str(result))
        ifile.close()
        ofile.close()
        return

    def inspect_to_csv(self, input_filename, output_filename):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Formats output file
            4. Gives url to 
        '''
        ifile = self.read(input_filename)
        ofile = self.append(output_filename)
        self.csv_format(ofile) # Formats output file for csv
        domainList = ifile.read().split()

        for i in range(0, len(domainList)):
            result = self.request(domainList[i])
            domain = result['url']
            row = domain + ","
            row += ",,,,," # This is the number of columns until the spreadsheet records AVs.
            scanResults = result['scans']
            
            for i in range(0, len(self.av_list)):
                row += self.cell(scanResults[self.av_list[i]])
                row += ","
                print(row)
            
            row += "\n"
            ofile.write(row)

        ifile.close()
        ofile.close()
        return

    def request(self, url):
        '''
            Given a url, will get the json results.
        '''
        # This section sends the url
        print("[ ] Sending url...")
        try:
            addResponse = self.add_url(url)
        except:
            print("Waiting 60s...")
            addResponse = self.add_url(url)
            pass

        if ('successfully' in addResponse['verbose_msg']):
            print("[+] URL Added: {}".format(url))
        else:
            logging.debug(addResponse)
            #print(json_response['verbose_msg'])
            return

        # This section you receive the JSON
        results = self.results(addResponse['scan_id'])
        return results

    def add_url(self, url):
        '''
            Adds a domain/url/ip to vt queue to analyze. 
        '''  
        params = {'apikey': self.api, 'url': url}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
        if (response.status_code == 403):
            logging.debug("403: {}".format(url))
            print("403") # DEBUGGING
            return
        try:
            json_response = response.json()
        except:
            print("Waiting 60s...")
            time.sleep(60)
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
            if (response.status_code == 403):
                logging.debug("403: {}".format(url))
                print("403") # DEBUGGING
                return
            json_response = response.json()
            pass
        return json_response
    
    def results(self, scan_id):
        '''
            Gets the results of a domain/url/ip request.
        '''
        params = {'apikey': self.api, 'resource':scan_id}
        headers = {"Accept-Encoding": "gzip, deflate",\
            "User-Agent" : "gzip,  My Python requests library example client or username"}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        json_response = response.json()
        return json_response
    
    def clean_json(self, jsonKinda):
        '''
            For whatever reason, VirusTotal gives you back a JSON that
            most libraries just don't like.
            None, single quotes and False are just a no-go.
            This will clean those up.
        '''
        clean = jsonKinda.replace("\'", "\"")
        clean = clean.replace("None", "0")
        clean = clean.replace("False", "0")
        clean = clean.replace("True", "1")
        return clean
    
    def csv_format(self, output_file):
        '''
            Creates a formatted csv, ready for data.
            Don't get output_file and output_filename confused.
            output_file is open.
        '''
        output_file.write("Domain,Detected,Clean,Suspicious,Malware,Malicious,ADMINUSLabs,AegisLab WebGuard,AlienVault,Antiy-AVL,Avira,Baidu-International,BitDefender,Blueliv,C-SIRT,Certly,CLEAN MX,Comodo Site Inspector,CyberCrime,CyRadar,desenmascara.me,DNS8,Dr.Web,Emsisoft,ESET,Forcepoint ThreatSeeker,Fortinet,FraudScore,FraudSense,G-Data,Google Safebrowsing,K7AntiVirus,Kaspersky,Malc0de Database,Malekal,Malware Domain Blocklist,Malwarebytes hpHosts,Malwared,MalwareDomainList,MalwarePatrol,malwares.com URL checker,Nucleon,OpenPhish,Opera,Phishtank,Quttera,Rising,SCUMWARE.org,SecureBrain,securolytics,Spam404,Sucuri SiteCheck,Tencent,ThreatHive,Trustwave,Virusdie External Site Scan,VX Vault,Web Security Guard,Webutation,Yandex Safebrowsing,ZCloudsec,ZDB Zeus,ZeroCERT,Zerofox,ZeusTracker,zvelo,AutoShun,Netcraft,NotMining,PhishLabs,Sophos,StopBadware,URLQuery\n")
        return

    def cell(self, av_result):
        '''
            Given a single av_result by vt,
            this will format an output.
            ex. {'detected': False, 'result': 'clean site'}
                'False/clean site'
        '''
        cell = str(av_result['detected'])
        cell += ";" + av_result['result']
        
        # Sometimes there aren't details.
        try:
            cell += ";" + av_result['detail']
        except:
            pass

        return cell
    
    def append(self, filename):
        '''
            Saves output to a file
        '''
        f = open(filename, 'a')
        return f
    
    def read(self, filename):
        '''
            Read from a file
        '''
        f = open(filename, 'r')
        return f
    
    def close(self, filename):
        '''
            Closes a file
        '''
        filename.close()
        return
    
