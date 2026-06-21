import os # We import the packages and modules
import scans
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import csv


class AutoScanHandler(FileSystemEventHandler): # We define the event handlery class.
    
    def __init__(self, op_file):
        self.op_file = op_file
        
    def on_created(self, event): # This method is inherited from the  watchdog class: 'FileSystemEventHandler'
        # This method triggers automatically when a new file is created.
        if event.is_directory:
            print(f"New folder detected: {event.src_path} (Doesn't require scan)")
            return() # If the event is a folder, the method ignores it.
        
        file_path = event.src_path
        print(f"New file detected! {file_path}")
        
        scans.scan_file(file_path, self.op_file) # We pass the file_path to be scanned.
        
def select_report_type(): # This function is for select in which type of file do you want to make the report.
    while True:
        print("""
1. TXT
2. HTML

9. Exit
          """)
        try:
            op_file = int(input(f"Which type of report do you prefer? "))
            if op_file == 9:
                print(f"Exiting...")
                exit()
            elif op_file == 1 or op_file == 2:
                return(op_file)
            else:
                print(f"Please enter a valid number.")
                continue
        except ValueError:
            print(f"Please enter a number, not a string. Please try again")
            continue
        
        
        
        
while True: # Main loop.

    print("""
1. Scan a individual file
2. Scan a path in real time
3. Scan a directory and its subdirectories.
4. Scan a CSV (list of files)

9. Exit
    """)
    while True:
        try:
            op_scan = int(input(f"What do you want to do? "))
            break
        except ValueError:
            print(f"Please enter a number, not a string. Please try again")
            continue
        
    if op_scan == 9:
        print(f"Exiting...")
        break

    if op_scan == 1:
        op_file = select_report_type()
        file_path = str(input(f"Write 0 for exit.\nEnter the file do you want to scan (C:\\example\\example.exe): ")).strip() 
        if file_path == '0':
            print(f"Exiting...")
            break
        scans.scan_file(file_path, op_file)
    elif op_scan == 2:
        op_file = select_report_type()
        mon_path = str(input(f"Write 0 for exit.\nEnter the path do you want to scan (C:\\example\\example.exe): ")).strip() 
        
        if mon_path == '0':
            print(f"Exiting...")
            break
        
        if not os.path.exists(mon_path):
            print("The path doesn't exists. Try again with an existing path")
            continue
                        
        event_handler = AutoScanHandler(op_file) # We create an instance of the class, we pass the variable op_file.
        observer = Observer() # We create a instance of the observer class (The watchdog motor).
        
        # We configure the observer by linking the path, the handler and disabling recursion.
        observer.schedule(event_handler, path=mon_path, recursive=False)
        observer.start()# We start the thread that is going to monitor the path
        
        try:
            while True:
                time.sleep(1) # Maintains the thread alive.
        except KeyboardInterrupt: # If the user stops the code with the keyboard, the tread stop.
            print(f"Stopping the file monitor...")
            observer.stop() # The observer stops.
        observer.join() # Wait until the thread of the observer totally stops.
        
    elif op_scan == 3:
        op_file = select_report_type()
        scan_path =  str(input(f"Write 0 for exit.\nEnter the path do you want to scan (C:\\example\\example.exe): ")).strip()

        if scan_path == '0':
            print(f"Exiting...")
            break
        
        if not os.path.exists(scan_path):
            print("The path doesn't exists. Try again with an existing path")
            continue
        
        for root, _, files in os.walk(scan_path): # We walk along the directory searching new subdirectories and files.
            for file in files: #
                full_path = os.path.join(root, file) # We join the new subdirectory or file with de scan_path to have the fullpath
                if os.path.isfile(full_path): # We use os to know if the full_path is a directory or a file
                    scans.scan_file(full_path, op_file) # If is a file we pass it to the scan function.
                    
    elif op_scan == 4:
        op_file = select_report_type()
        path_csv = str(input(f"Which is the path of the csv file? "))
        files = []
        with open(path_csv, 'r') as f:
            csv_file = csv.reader(f) # It converts the csv file in a iterable object.
            for row in csv_file: # We iterate over the object, this return a list for each tuple.
                for file_path in row: # We iterate another time, this time it return a string for each element of the list.
                    files.append(file_path) # Each add each string to the list as a element.
            for i in files: # We iterate for each element of the list and we pass it to the scan function.
                
                scans.scan_file(i, op_file)         
                
    else:
        print(f"Please, enter a valid number.")
        continue


            

      
    
