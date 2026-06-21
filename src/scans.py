import vt # We import the packages and modules
import requests
import os
import report_txt as report_txt
import magic
import report_txt
import report_html
import yara
import hashlib as hash
from dotenv import load_dotenv

load_dotenv() # We load the .env function
vt_api_key = os.getenv("vt_api_key") # We use os to extract a variable of the .env
mb_api_key = os.getenv("mb_api_key")

class File(): # We will treat the file las an object.
    def __init__(self, path, hash, type): # We define de class constructor.
        self.path = path
        self.hash = hash
        self.type = type
        
    def __str__(self): # We define the object string representation.
        return(f"""
FILE OVERVIEW
--------------------------
Path: {self.path}
Hash: {self.hash}       
Type: {self.type}          
               """)
        
rule_list = {}
# We create a loop for walk along all the yara rules in the folder and compile one by one.
for root, _, files in os.walk('.\\yara_rules'): 
    for file_name in files:
        if file_name.endswith('.yar') or file_name.endswith('.yara'): # We validate the file extension to know if the file is a yara rule.
            full_path = os.path.join(root, file_name)
            try:
                rule = yara.compile(full_path) # We use yara.compile to compile the rule.
                rule_list[full_path] = rule # We create a record in the dictionary that asociate the path of the rule withe the rule compiled.
            except yara.Error as e:
                print(f"The rule {file_name} has given the error: {e}")

def scan_file(file_path, op_file):
    if not os.path.exists(file_path):
        print(f"The file or path '{file_path}' doesn't exist.")
        return()
    
    try:
        # We open the file reading his binary.
        with open(file_path, "rb") as f: # r = read | b = binary.
            digest = hash.file_digest(f, "sha256")
            file_hash = digest.hexdigest()
            file_type = magic.from_file(file_path, mime=True)  
        obj_file = File(file_path, file_hash, file_type) # We create the file object.
        print(obj_file)
        report_vt, report_mb = signatures(obj_file) 
        report_yara = static(obj_file, rule_list)  
    except Exception as e:
            print(f"Error trying to scan the file {file_path}: {e}")

    if op_file == 1:      
        report_txt.generate_txt(obj_file, report_vt, report_mb, report_yara)
    elif op_file == 2:
        report_html.generate_html(obj_file, report_vt, report_mb, report_yara)
    return(None)       


def signatures(obj_file):
    
    # ******************** VIRUS TOTAL SCAN ***************************
    print(f"VIRUS TOTAL SCAN")
    print(f"--------------------------")
    vt_client = vt.Client(f"{vt_api_key}")
    while True:
        try:
            print(f"< We are querying VirusTotal for the hash > ")
            analysis = vt_client.get_object(f"/files/{obj_file.hash}")
            stats = analysis.last_analysis_stats
            report_vt = (f""">>> The hash {obj_file.hash} was found on Virus Total <<<
-> Malicious: {stats['malicious']}         
-> Suspicious: {stats['suspicious']}         
-> Harmless: {stats['harmless']}      
-> Enlace: https://www.virustotal.com/gui/file/{obj_file.hash}   
                """)
            print(f"< The hash has been found in VirusTotal >")
        except vt.error.APIError as error:
            if error.code == 'NotFoundError':
                report_vt = (f">>> The hash {obj_file.hash} was not found on VirusTotal <<<")
                print(f"< The hash hasn't been found on VirusTotal >")
            else:
                print(f"An error occurred with the API.")
        break
    vt_client.close()

    # ******************** MALWARE BAZAAR SCAN ***************************
    print(f"\nMALWARE BAZAAR SCAN")
    print(f"--------------------------")
    data = {
        'query': 'get_info',
        'hash': obj_file.hash
    }
    headers = {
        'Auth-Key': f"{vt_api_key}"
    }
    url = "https://mb-api.abuse.ch/api/v1/"
    
    response = requests.post(url, data=data,headers=headers, timeout=10)
    response_json = response.json()
    status = response_json.get("query_status")
    
    if status == "hash_not_found":
        print(f"< The hash hasn't been found on Malware Baazar >")
        report_mb = (f">>> The hash {obj_file.hash} was not found on Malbazaar <<<")
    else:
        info = response_json.get("data", [{}])[0]
        print(f"< The hash has been found in Malware Bazaar >")
        report_mb = (f""">>> The hash {obj_file.hash} was found on Malware bazaar. It is malicius. <<<
    -> Name: {info.get('file_name')}
    -> Signature: {info.get('signature')}
    -> Type: {info.get('file_type')}
    -> Size: {info.get('file_size')}
    -> Tags: {info.get('tags')}
              """)
        
    return(report_vt, report_mb)

def static (obj_file, rule_list):
    print(f"\nYARA RULES SCAN")
    print(f"--------------------------")
    
    if not rule_list:
        print("< No YARA rules loaded or compiled. >")
        return(None)
    
    match_found = False
    
    for full_path, rules in rule_list.items():

        
        matches = rules.match(obj_file.path)
        if matches:
            match_found = True
            print(f">>> The rule {full_path} has been matched with {obj_file.path }<<<")
            
            report1 = (f">>> The rule {full_path} has been matched with {obj_file.path }<<<")
            report2 = (f"Result: {matches}")
            report_yara = report1 + report2
            return(report_yara) 
    
    if not match_found:
        print(f"< There is no match for this file. >")
        report_yara = (f"There is no match for this file.")
        return(report_yara) 
    
