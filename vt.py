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
from pathlib import Path
import Mallector, requests, logging
import time, DailySave, os, datetime, sys


class VirusTotal:

    def __init__(self):
        self.api = ""
        self.av_list = open('data/VT-AVs', 'r').read().splitlines()
        self.potentials = None
        self.potentials_file = 'data/Potentials.txt'
        self.blk = None
        self.blk_file = 'data/GlobalBlacklist.txt'
        self.analysis = None
        self.analysis_file = 'data/Full-Analysis.csv'
        self.processed = None
        self.processed_file = 'data/Processed_file.txt'
        self.cycles = 0
        self.reprocess_line = 0 # Used to determine what line the reprocessing function is on
        self.data = [self.analysis_file, self.blk_file, self.potentials_file, self.processed_file]
        logging.basicConfig(filename='logs/vt.log', level=logging.DEBUG, format='%(asctime)s %(message)s')
        return
    
    def files_exist(self, filename):
        the_file = Path(filename)
        if (the_file.is_file()):
            return True
        return False
    
    def inspect(self, input_filename):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Gives url to 
        '''
        analysis = open(self.analysis_file, 'a')
        ifile = open(input_filename, 'r')
        domainList = ifile.read().split()

        for i in range(0, len(domainList)):
            result = self.request(domainList[i])
            self.analysis.write(str(result))
        ifile.close()
        analysis.close()
        return

    def inspect_to_csv(self, input_filename):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Formats output file
            4. Gives url to 
        '''
        # Input file for domain_list
        ifile = open(input_filename, 'r')
        # Analysis Output file. Contains all AV results per request
        
        # DEBUG TEST #
        #analysis = open(self.analysis_file, 'a')
        analysis = open('test-one.csv', 'a')
        self.csv_format() # Formats output file for csv
        domainList = ifile.read().split()

        for i in range(0, len(domainList)):
            print("{}/{}".format(i, len(domainList)))
            
            try:
                result = self.request(domainList[i])
                domain = result['url']
                row = domain + ","
                ts = time.time()
                timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                row += ",{},,,,,".format(timestamp) # This is the number of columns until the spreadsheet records AVs.
                scanResults = result['scans']
                
                for i in range(0, len(self.av_list)):
                    try:
                        row += self.cell(scanResults[self.av_list[i]])
                    except:
                        pass
                    row += ","
                
                row += "\n"
                try:
                    analysis.write(row)
                except:
                    logging.exception("message")

            except:
                print("Special Excpetion. Something Broke.")
                
                try:
                    self.analysis.write("BROKEN\n")

                except:
                    logging.exception("message")

                logging.exception("message")
                pass

        ifile.close()
        analysis.close()
        return

    def persistent_analysis(self, api_key):
        '''
            Driver.
            1. Reads domain list from file
            2. Creates output file
            3. Formats output file
            4. Gives url to 
        '''
        self.api = api_key

        # Determine if files exist, if they don't create them.
        # Full-Analysis.txt
        if (self.files_exist(self.analysis_file)):
            self.analysis = open(self.analysis_file, 'a')

        else:
            self.csv_format() # Formats output file for csv
            self.analysis.flush()
            os.fsync(self.analysis.fileno())

        # GlobalBlacklist.txt
        if not (self.files_exist(self.blk_file)):
            self.blk = open(self.blk_file, 'a')
            self.blk.close()

        # Blacklist output file. New file each day.
        # Removing blacklist file per day. Going to make it one master blacklist.
        #with DailySave.RotatingFileOpener('blacklist', prepend='blacklist-', append='.txt') as bl:
        collector = Mallector.Mallector()

        while True:

            # Number of cycles
            print("Number of cycles: {}".format(self.cycles))

            # Updates feeds
            collector.update_feeds()

            # Gathers all new domains from feeds
            collector.collect(self.potentials_file)

            # Cleans all duplicates in all three files.
            collector.dedupe_all()

            # Cleans all domains that have already been processed
            collector.already_processed()

            # Creates a list of potentially malicious domains from potential.txt
            new_potentials = self.new_pdomains()
            if (new_potentials):

                # Analysis Output file. Contains all AV results per request
                self.blk = open(self.blk_file, 'a')
                self.potentials = open(self.potentials_file, 'r')
                self.processed = open(self.processed_file, 'a')
                domainList = self.potentials.read().split()

                for i in range(0, len(domainList)):
                    print("{}/{}".format(i, len(domainList)))
                    
                    try:
                        result = self.request(domainList[i])

                        # Determine if domain is malicious
                        if (self.is_malicious(result)):
                            print('{} is MALICIOUS!'.format(domainList[i]))
                            self.blk.write(domainList[i] + "\n")
                            self.blk.flush()
                            os.fsync(self.blk.fileno())
                        else:
                            print('{} is NOT malicious!'.format(domainList[i]))
                            self.processed.write(domainList[i] + "\n")
                            self.processed.flush()
                            os.fsync(self.processed.fileno())

                        self.csv_output(result)

                    except:
                        print("Check persistent analysis..")
                        logging.debug("Check persistent analysis.\n")
                        logging.exception("message")
                        pass
                
                self.analysis.close()
                self.blk.close()
                self.potentials.close()
                self.processed.close()

            else:
                logging.info("No new potentially malicious domains.")
                logging.info("Reprocessing starting on line {}".format(self.reprocess_line))
                
                # Reprocessed the processed list to see if anything has changed
                self.reprocess()

            # Keep track of the number of times this program has looped.
            self.cycles += 1

        return
    
    def reprocess(self):
        self.processed = open(self.processed_file, 'r')
        processed_list = self.processed.read().split()
        start = time.time()
        time_lapsed = time.time()

        while ((time_lapsed - start) < 3600):
            print("{}/{}".format(self.reprocess_line, len(processed_list)))
            
            try:
                result = self.request(processed_list[self.reprocess_line])

                # Determine if domain is malicious
                if (self.is_malicious(result)):
                    print('{} is MALICIOUS!'.format(processed_list[self.reprocess_line]))
                    self.blk.write(processed_list[self.reprocess_line] + "\n")
                    self.blk.flush()
                    os.fsync(self.blk.fileno())
                else:
                    print('{} is NOT malicious!'.format(processed_list[self.reprocess_line]))
                    self.processed.write(processed_list[self.reprocess_line] + "\n")
                    self.processed.flush()
                    os.fsync(self.processed.fileno())

                self.csv_output(result)

            except:
                print("Check reprocess...")
                logging.debug("Check reprocess.\n")
                logging.exception("message")
                pass

            self.reprocess_line +=1
            time_lapsed = time.time()

        return

    def csv_output(self, result):
        domain = result['url']
        row = domain + ","
        ts = time.time()
        timestamp = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        row += "{},,,,,,".format(timestamp) # This is the number of columns until the spreadsheet records AVs.
        scanResults = result['scans']
        
        for i in range(0, len(self.av_list)):
            try:
                row += self.cell(scanResults[self.av_list[i]])
            except:
                pass
            row += ","
        
        row += "\n"
        self.analysis.write(row)
        self.analysis.flush()
        os.fsync(self.analysis.fileno())
        return

    def request(self, url):
        '''
            Given a url, will get the json results.
        '''
        # This section sends the url
        print("[ ] Sending url...{}".format(url))
        try:
            addResponse = self.add_url(url)
        except:
            print("Waiting 60s...")
            self.blk.flush()
            os.fsync(self.blk.fileno())
            pass

        if ('successfully' in addResponse['verbose_msg']):
            print("[+] URL Added: {}".format(url))
        else:
            logging.debug(addResponse)
            logging.exception("message")
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
            print("403: ERROR WITH API-KEY") # DEBUGGING
            sys.exit(1)

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
            logging.exception("message")
            pass
        return json_response
    
    def new_pdomains(self):
        
        # Input file for domain_list
        try:
            self.potentials = open(self.potentials_file, 'r')

        except FileNotFoundError:
            logging.info("{} not found. Creating one now.".format(self.potentials_file))
            self.potentials = open(self.potentials_file, 'a')
            self.potentials.close()
            self.potentials = open(self.potentials_file, 'r')
            logging.exception("message")
            pass     

        potentials_list = self.potentials.read().split()
        self.potentials.close()        

        try:
            blkout = open(self.blk_file, 'r')

        except FileNotFoundError:
            logging.info("{} not found. Creating one now.".format(self.blk_file))
            blkout = open(self.blk_file, 'a')
            blkout.close()
            blkout = open(self.blk_file, 'r')
            logging.exception("message")
            pass

        blkout_list = blkout.read().split()
        blkout.close()

        try:
            processed = open(self.processed_file, 'r')

        except FileNotFoundError:
            logging.info("{} not found. Creating one now.".format(self.processed_file))
            processed = open(self.processed_file, 'a')
            processed.close()
            processed = open(self.processed_file, 'r')
            logging.exception("message")
            pass

        processed_list = processed.read().split()
        processed.close()

        temp_total_list = blkout_list + processed_list
        if not (list(set(potentials_list) - set(temp_total_list))):
            return False
        return True

    def results(self, scan_id):
        '''
            Gets the results of a domain/url/ip request.
        '''
        params = {'apikey': self.api, 'resource':scan_id}
        headers = {"Accept-Encoding": "gzip, deflate",\
            "User-Agent" : "gzip,  My Python requests library example client or username"}
        response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
        
        # There's a case where the response is empty
        if not (response):
            return
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
    
    def csv_format(self):
        '''
            Creates a formatted csv, ready for data.
            Don't get output_file and output_filename confused.
            output_file is open.
        '''
        self.analysis = open(self.analysis_file, 'a')
        self.analysis.write("Domain,Timestamp,Detected,Clean,Suspicious,Malware,Malicious,ADMINUSLabs,AegisLab WebGuard,AlienVault,Antiy-AVL,Avira,Baidu-International,BitDefender,Blueliv,C-SIRT,Certly,CLEAN MX,Comodo Site Inspector,CyberCrime,CyRadar,desenmascara.me,DNS8,Dr.Web,Emsisoft,ESET,Forcepoint ThreatSeeker,Fortinet,FraudScore,FraudSense,G-Data,Google Safebrowsing,K7AntiVirus,Kaspersky,Malc0de Database,Malekal,Malware Domain Blocklist,Malwarebytes hpHosts,Malwared,MalwareDomainList,MalwarePatrol,malwares.com URL checker,Nucleon,OpenPhish,Opera,Phishtank,Quttera,Rising,SCUMWARE.org,SecureBrain,securolytics,Spam404,Sucuri SiteCheck,Tencent,ThreatHive,Trustwave,Virusdie External Site Scan,VX Vault,Web Security Guard,Webutation,Yandex Safebrowsing,ZCloudsec,ZDB Zeus,ZeroCERT,Zerofox,ZeusTracker,zvelo,AutoShun,Netcraft,NotMining,PhishLabs,Sophos,StopBadware,URLQuery\n")
        self.analysis.flush()
        os.fsync(self.analysis.fileno())
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
            logging.exception("message")
            pass

        return cell

    def malcheck(self, url):
        result = self.request(url)
        if (self.is_malicious(result)):
            conclusion = "MALICIOUS"
        elif (not self.is_malicious(result)):
            conclusion = "NOT malicious"
        else:
            print('mal_check broke, but because of is_malicious()')
            logging.debug('mal_check broke, but because of is_malicious()')
        print("{}: {}".format(conclusion, url))
        return 
    
    def is_malicious(self, result):
        '''
            Determines if a domain is malicious.
            If both Forcepoint ThreatSeeker and Fortinet return True,
            it is malicious.
        '''
        try:
            if (result['scans']['Forcepoint ThreatSeeker']['detected'] & result['scans']['Fortinet']['detected']):
                return True
        except:
            logging.warning("{} could not be determine as malicious or not. AVs on VT might not have analyzed domain.")
            logging.exception("message")
            pass
        return False


def main():
    print("Welcome to VirusTotalWrapper!")
    print("If you don't have an API-Key, get one for free at VirusTotal.com.")
    api = input("Enter your API-Key: ")

    c = VirusTotal()
    c.persistent_analysis(api)

if __name__ == "__main__":
    main()