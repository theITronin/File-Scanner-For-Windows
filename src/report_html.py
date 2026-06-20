import datetime as dt
import os
        
def generate_html(obj_file, report_vt, report_mb, report_yara): # This function is use it for the creation of the html report.
    file_name = os.path.basename(obj_file.path) # We use os to know the file name
    date = dt.datetime.now() # We write in "date" the actual datetime.
    report_file = date.strftime("%Y-%m-%d_%H-%M-%S") + file_name + ".html" # We write the name which is composed by the datetime + the file name + the file extension.

    
    html = (f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">

<style>

body {{
    font-family: Segoe UI, Arial, sans-serif;
    background-color: #f5f7fa;
    margin: 40px;
}}

h1 {{
    color: #4a00ff;
    border-bottom: 3px solid #4a00ff;
    padding-bottom: 10px;
}}

.card {{
    background-color: white;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}}

.card h2 {{
    margin-top: 0;
    color: #333;
}}

.info-table {{
    width: 100%;
    border-collapse: collapse;
}}

.info-table td {{
    padding: 10px;
    border-bottom: 1px solid #ddd;
}}

.label {{
    font-weight: bold;
    width: 150px;
}}

pre {{
    white-space: pre-wrap;
    word-wrap: break-word;
    background-color: #f8f9fc;
    padding: 15px;
    border-radius: 5px;
    border-left: 4px solid #4a00ff;
}}

</style>
</head>

<body>

<h1>ANALYSIS REPORT</h1>

<div class="card">
    <h2>File Information</h2>

    <table class="info-table">
        <tr>
            <td class="label">File Path</td>
            <td>{obj_file.path}</td>
        </tr>

        <tr>
            <td class="label">File Hash</td>
            <td>{obj_file.hash}</td>
        </tr>

        <tr>
            <td class="label">File Type</td>
            <td>{obj_file.type}</td>
        </tr>
    </table>

</div>

<div class="card">
    <h2>VirusTotal Report</h2>
    <pre>{report_vt}</pre>
</div>

<div class="card">
    <h2>Malware Bazaar Report</h2>
    <pre>{report_mb}</pre>
</div>

<div class="card">
    <h2>YARA Rules Matches</h2>
    <pre>{report_yara}</pre>
</div>

</body>
</html>
""")
    
    with open (report_file, "w", encoding="utf-8") as html_file:
        html_file.write(html)
        
    

