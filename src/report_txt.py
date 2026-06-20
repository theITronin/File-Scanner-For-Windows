import datetime as dt
import os

def generate_txt(obj_file, report_vt, report_mb, report_yara): # This function is use it for the creation of the txt report.
    file_name = os.path.basename(obj_file.path) # We use os to know the file name
    date = dt.datetime.now() # We write in "date" the actual datetime.
    report_file = date.strftime("%Y-%m-%d_%H-%M-%S") + file_name + ".txt" # We write the name which is composed by the datetime + the file name + the file extension.
    print(report_file)
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"""
                                -------------------
                                | ANALYSIS REPORT |
                                -------------------
                                           
File Path = {obj_file.path}
File Hash = {obj_file.hash}
File Type = {obj_file.type}
                """)
        f.write(f"""
VIRUSTOTAL REPORT
{report_vt} 
                """)
       
        f.write(f"""
MALWARE BAZAAR REPORT
{report_mb} 
                """)
        
        f.write(f"""
YARA RULES MATCHES
{report_yara} 
                """)
    
    return(None)
    







    
    