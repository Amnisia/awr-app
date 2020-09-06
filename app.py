from flask import Flask, request, redirect, url_for, render_template, send_from_directory, session
from flask_bootstrap import Bootstrap
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, exc, text

import requests
import IdcsClient
import json
import os
import zipfile
import math
import csv
import glob

import cx_Oracle
import pandas as pd
import logging
import oci
import io
import sys
from oci.config import validate_config
from oci.object_storage import ObjectStorageClient



'''
AWR Automation Script for .out file automated analysis report generation
Last Updated: July 2020
'''

UPLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__)) + '/uploads/'
DOWNLOAD_FOLDER = os.path.dirname(os.path.abspath(__file__)) + '/downloads/'

ALLOWED_EXTENSIONS = {'txt', 'zip'}

app = Flask(__name__, static_url_path="/static")
Bootstrap(app)
DIR_PATH = os.path.dirname(os.path.realpath(__file__))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

# Limit upload size of files up to 100 MB
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.secret_key = 'secret'

# Definition of the /auth route
@app.route('/auth', methods=['POST', 'GET'])
def auth():
    session.clear()
    # Loading the configurations
    options = getOptions()
    # Authentication Manager loaded with the configurations
    am = IdcsClient.AuthenticationManager(options)
    '''
    Using Authentication Manager to generate the Authorization Code URL, passing the
    application's callback URL as parameter, along with code value and code parameter
    '''
    url = am.getAuthorizationCodeUrl(options["redirectURL"], options["scope"], "1234", "code")

    # Redirecting the browser to the Oracle Identity Cloud Service Authorization URL.
    return redirect(url, code=302)


def getAccessToken(URL, clientId, clientSecret):
    data = {
        'grant_type': 'client_credentials',
        'scope': 'urn:opc:idm:__myscopes__'
    }
    # Request for auth token
    response = requests.post(URL + '/oauth2/v1/token', data=data, verify=False, auth=(clientId, clientSecret))
    # Parses response into JSON format
    res = response.json()
    # Parse access token
    access_token = res['access_token']
    return access_token


# Function used to load the configurations from the config.json file
def getOptions():
    fo = open("/home/opc/Desktop/nginxawrtool/p3_env/config.json", "r")
    config = fo.read()
    options = json.loads(config)
    return options


# Definition of the /logout route
@app.route('/logout', methods=['POST', 'GET'])
def logout():
    id_token = (session.get("id_token", None))

    options = getOptions()

    url = options["BaseUrl"]
    url += options["logoutSufix"]
    url += '?post_logout_redirect_uri=http%3A//localhost%3A8000&id_token_hint='
    url += id_token
    
    # check logout url
    print("checking logout url: " + str(url))
    
    # clears Flask client-side session (also works on refresh of browser)
    session.clear()

    # Redirect to Oracle Identity Cloud Service logout URL
    return redirect(url, code=302)


@app.route('/')
def login():
    return render_template('login.html')


@app.route('/home', methods=['POST', 'GET'])
def home():
    
    # first call IDCS API to get id_token; should return 400 status if not authenticated
    # if statement to kick you back to login if status is 400
    # if authenticated, status 200 allows app to render protected html

    options = getOptions()

    # 'code' is authorization code which is needed to get id_token
    # uses flask.request library (different from Python requests library)
    session['code'] = request.args.get('code')
    u = None
    try: 
    	#Authentication Manager loaded with the configurations.
    	am = IdcsClient.AuthenticationManager(options)
    	#Using the Authentication Manager to exchange the Authorization Code to an Access Token.
    	ar = am.authorizationCode(session['code'])
    	#Get the access token as a variable
    	access_token = ar.getAccessToken()
    	#User Manager loaded with the configurations.
    	um = IdcsClient.UserManager(getOptions())
    	#Using the access_token value to get an object instance representing the User Profile.
    	u = um.getAuthenticatedUser(access_token)
    	#Getting the user details in json object format.
    	session['userName'] = u.getUserName()
    	print(session['userName'])
    except:
        print("Auth code Error") 
    
    data = {
        'grant_type': 'authorization_code',
        'code': session['code'],
        'redirect_uri': options['redirectURL']
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
    }

    response = requests.post(options['BaseUrl'] + '/oauth2/v1/token?', data=data, headers=headers,                        auth=(options['ClientId'], options['ClientSecret']))

    session['id_token'] = response.json().get("id_token")   

    # Parse files that user uploads to be analyzed
    print('Determine POST method')
    if request.method == 'POST':
        if 'file' not in request.files:
            print('No file attached in request')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            print('No file selected')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            print('File successfully found')
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            awr_script(os.path.join(app.config['UPLOAD_FOLDER'], filename), filename, session['userName'])
            return redirect(url_for('uploaded_file'))
    
    if u is None:
        return render_template('login.html')
    #print('Printing response status code:' + str(response.status_code))
    #if str(response.status_code) != "200":
    #    return render_template('login.html')
    
    return render_template('index.html')


# Where AWR app.py starts -------------------------------
@app.route('/home')
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/home')
def process_file(path, filename):
    with open(os.path.join(app.config['UPLOAD_FOLDER'], filename)) as f:
        with open(app.config['DOWNLOAD_FOLDER'] + filename, 'w') as f1:
            for line in f:
                f1.write(line)
            f1.write('This is a test')


@app.route('/home')
def awr_script(path, filename, userName):
    filevalues = []

    with zipfile.ZipFile(os.path.join(app.config['UPLOAD_FOLDER'], filename), "r") as allFiles:
        allFiles.extractall(app.config['DOWNLOAD_FOLDER'])
    try:
        for dirEntry in os.scandir(app.config['DOWNLOAD_FOLDER']):  # replace temp with download folder
            if dirEntry.name.endswith(".out"):
                with open(dirEntry) as fp:

                    print ("\n \n")
                    print ("STEP 0: Parsing the following file:")
                    print (dirEntry)
                    print ("\n \n")

                    master_dictionary = {
                        "DB_NAME": None ,
                        "VERSION": None ,
                        "HOSTS": None ,
                        "NUM_CPU_SOCKETS": None ,
                        "NUM_CPU_CORES": None ,
                        "PHYSICAL_MEMORY_GB": None
                    }

                    begin_dictionary = {
                        "~~BEGIN-OS-INFORMATION~~": None,
                        "~~BEGIN-MEMORY~~": None,
                        "~~END-SIZE-ON-DISK~~": None,
                        "~~END-DATABASE-PARAMETERS~~": None,
                        "~~BEGIN-IOSTAT-BY-FUNCTION~~": None,
                        "~~END-IOSTAT-BY-FUNCTION~~": None,
                        "~~BEGIN-MAIN-METRICS~~": None,
                        "~~END-MAIN-METRICS~~" : None
                    }

                    # Read in the entire file and close it after
                    entireFile = fp.readlines()
                    fp.close()

                    # Initialize Variables
                    i = 0
                    counter = 0
                    found = False

                    # Store the indices of the sections of the .out files that are of importance for parsing
                    print("Step 1: Storing Important .out File Indices...")
                    for line in entireFile:
                        for item in begin_dictionary:
                            if item in line:
                                begin_dictionary[item] = entireFile.index(line)
                    print("Done. \n")

                    print (begin_dictionary)
                    print ("\n")

                    # Search for values for DB_NAME, VERSION, HOSTS, NUM_CPU_SOCKETS, NUM_CPU_CORES
                    print("Step 2: Calculate DB_NAME, VERSION, HOSTS, NUM_CPU_SOCKETS, NUM_CPU_CORES..., and PHYSICAL_MEMORY_GB")
                    while found == False:

                        try:
                            value = entireFile[list(begin_dictionary.values())[0] + i]
                            #print("In Step 2, here is the line being checked: " + value)
                            for item in master_dictionary:
                                if item in value:
                                    split_string = value.split()
                                    master_dictionary[item] = split_string[1]
                                    counter += 1
                        except:
                            print ("ERROR when calculating DB Name, Version, Hosts, Num CPU Sockets, Num CPU Cores, PHYSICAL_MEMORY_GB - file may be corrupted")
                            print("Unexpected error:", sys.exc_info()[0])
                            print("Unexpected error:", sys.exc_info()[1])
                        if counter == 6 or i >25:
                            found = True
                        i += 1
                        print (i)
                    print("Done. Values Gathered so Far: {} \n".format(master_dictionary))

                    # Calculate # RAC NODES and RAC status
                    print("Step 3: Calculating # RAC NODES and RAC status...")
                    try:
                        if ',' in master_dictionary["HOSTS"]:
                            master_dictionary["#RAC Nodes"] = len(master_dictionary["HOSTS"].split(sep=','))
                            master_dictionary["RAC"] = "YES"
                        else:
                            master_dictionary["#RAC Nodes"] = 1
                            master_dictionary["RAC"] = "NO"
                        print("Done. Values Gathered so Far: {} \n".format(master_dictionary))
                    except:
                        print ("ERROR when calculating RAC NODES and RAC status - file may be corrupted")


                    # Calculate DBSize(GB)
                    try:
                        print("Step 4: Calculating DBSize(GB)...")
                        snap_size = entireFile[list(begin_dictionary.values())[2]-2]
                        split_string2 = snap_size.split()
                        master_dictionary["DBSize(GB)"] = split_string2[1]
                        print("Done. Values Gathered so Far: {} \n".format(master_dictionary))
                    except:
                        print ("ERROR when calculating DBSize - file may be corrupted")

                    # Initialize Variables
                    i = 2
                    found = False
                    counter = 0

                    # Calculate SGA and PGA
                    print("Step 5: Calculating SGA and PGA...")
                    try:
                        while found == False:
                            value = entireFile[list(begin_dictionary.values())[3] - i]
                            if "sga_max_size" in value:
                                split_string = value.split()
                                master_dictionary["SGA"] = round(int(split_string[1])/1000000000, 1)
                                counter +=1
                            if "pga_aggregate_target" in value:
                                split_string = value.split()
                                master_dictionary["PGA"] = round(int(split_string[1]) / 1000000000, 1)
                                counter += 1
                            if counter == 2:
                                found = True
                            i += 1
                        print("Done. Values Gathered so Far: {} \n".format(master_dictionary))
                    except:
                        print ("ERROR when calculating SGA and PGA - file may be corrupted")

                    # Initialize Variables
                    i = 1
                    found = False
                    total_buffer_cache_reads = 0
                    total_direct_reads = 0
                    total_direct_writes = 0
                    total_LGWR = 0

                    # Calculate Read/Writes to determine workload type
                    print("Step 6: Calculating Read/Writes to determine workload type...")
                    try:
                        while found == False:
                            value = entireFile[list(begin_dictionary.values())[4] + i]
                            if list(begin_dictionary.values())[4] + i == list(begin_dictionary.values())[5]:
                                found = True
                            if "Buffer Cache Reads" in value:
                                split_string = value.split()
                                total_buffer_cache_reads += (int(split_string[4]) + int(split_string[5]) + int(split_string[6]) + int(split_string[7]))
                            elif "Direct Reads" in value:
                                split_string = value.split()
                                total_direct_reads += (int(split_string[3]) + int(split_string[4]) + int(split_string[5]) + int(split_string[6]))
                            elif "Direct Writes" in value:
                                split_string = value.split()
                                total_direct_writes += (int(split_string[3]) + int(split_string[4]) + int(split_string[5]) + int(split_string[6]))
                            elif "LGWR" in value:
                                split_string = value.split()
                                total_LGWR += (int(split_string[2]) + int(split_string[3]) + int(split_string[4]) + int(split_string[5]))
                            i += 1

                        workload_type = "None"
                        total_reads = total_buffer_cache_reads + total_direct_reads
                        total_writes = total_direct_writes + total_LGWR
                        # Mixed workload if difference b/w reads and writes is less than 20%
                        if math.isclose(total_reads, total_writes, rel_tol=0.20):
                            workload_type = 'Mixed Workload'
                        elif total_reads > total_writes:
                            workload_type = 'OLAP'
                        elif total_reads < total_writes:
                            workload_type = 'OLTP'
                        master_dictionary["Reads/Writes"] = workload_type
                        master_dictionary["Total Reads"] = total_reads
                        master_dictionary["Total Writes"] = total_writes
                        print("Total Buffer Cache Reads: {} \nTotal Direct Reads: {} \nTotal Direct Writes: {} \nTotal LGWR: {} ".format(total_buffer_cache_reads, total_direct_reads, total_direct_writes, total_LGWR))
                        print("Total Reads: {} \nTotal Writes: {} \nWorkload Type: {} ".format(total_reads, total_writes, workload_type))
                        print("Done. Values Gathered so Far: {} \n".format(master_dictionary))
                    except:
                        print ("ERROR when calculating Reads and Writes - file may be corrupted")
                    
                    # Initialize Variables for Step 6.5
                    i = 4
                    found = False
                    total_os_cpu = 0.0
                    total_os_cpu_max = 0.0
                    max_os_cpu_max = 0.0
                    average_os_cpu = 0.0
                    average_os_cpu_max = 0.0

                    # Calculate os_cpu and os_cpu_max
                    print("Step 6.5: Calculating os_cpu and os_cpu_max averages, and os_cpu_max max...")
                    try:
                        while found == False:
                            value = entireFile[list(begin_dictionary.values())[6] + i]
                            if list(begin_dictionary.values())[6] + i == list(begin_dictionary.values())[7]-1:
                                found = True
                            else:
                                split_string = value.split()
                                if value != "":
                                    if float(split_string[0]):
                                        #it's a snap, so let's get the os_cpu and os_cpu_max values, at index values of 4 and 5, respectively
                                        total_os_cpu += float(split_string[4])
                                        total_os_cpu_max += float(split_string[5])
                                        
                                        #get the new os_cpu_max maximum, if applicable
                                        if (float(split_string[5])) > max_os_cpu_max:
                                            max_os_cpu_max = float(split_string[5])

                                i += 1
                        
                        # We are done parsing the file, Let's compute the averages now and store in dicts
                        snap_counts = i-4 #subtract total for row lines that are not snap ids
                        average_os_cpu = total_os_cpu / snap_counts
                        average_os_cpu_max = total_os_cpu_max / snap_counts
                        
                        # Round with precision of 2 for 2 decimal places
                        master_dictionary["average_os_cpu"] = round(average_os_cpu, 2)
                        master_dictionary["average_os_cpu_max"] = round(average_os_cpu_max, 2)
                        master_dictionary["max_os_cpu_max"] = round(max_os_cpu_max,2)
                        
                        print("average_os_cpu: {} \naverage_os_cpu_max: {} \nmax_os_cpu_max: {} ".format(average_os_cpu, average_os_cpu_max, max_os_cpu_max))
                        print("Done. Values Gathered so Far: {} \n".format(master_dictionary))
                        
                    except:
                        print("ERROR when calculating os_cpu and os_cpu_max fields - file may be corrupted")
                        print("Unexpected error:", sys.exc_info()[0])
                        print("Unexpected error:", sys.exc_info()[1])


                    # Restructure Dictionary for CSV Output Compatability
                    master_dictionary['DBName'] = master_dictionary.pop('DB_NAME')
                    master_dictionary['Version'] = master_dictionary.pop('VERSION')
                    master_dictionary['Servers'] = master_dictionary.pop('HOSTS')
                    master_dictionary['Sockets'] = master_dictionary.pop('NUM_CPU_SOCKETS')
                    master_dictionary['Cores'] = master_dictionary.pop('NUM_CPU_CORES')

                    filevalues.append(master_dictionary)

        # Output Values Gathered to CSV File
        print("Step 7: Outputting Values Gathered to CSV File...")
        with open('./downloads/AWR_Report_Data.csv', 'w', newline='') as file:
            fieldnames = ['DBName', 'Version', 'RAC', '#RAC Nodes', 'Servers', 'Sockets', 'Cores', 'SGA', 'PGA', 'DBSize(GB)', 'Reads/Writes', 'Total Reads', 'Total Writes', 'PHYSICAL_MEMORY_GB', 'average_os_cpu', 'average_os_cpu_max', 'max_os_cpu_max']
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for master_dictionary in filevalues:
                print("Writing {} values to csv...".format(master_dictionary['DBName']))
                writer.writerow(master_dictionary)
        file.close()
        print("Done.\n")

        print("Begin Object Storage")
        bucket_name = "bucket-awr-out-files"
        validate_config(config)
        object_storage_client = ObjectStorageClient(config)
        namespace = object_storage_client.get_namespace().data

        for dirEntry in os.scandir(app.config['UPLOAD_FOLDER']):
            if dirEntry.name.endswith(".zip"):
                FILE_NAME = dirEntry.name
                print(UPLOAD_FOLDER + FILE_NAME)
                try:
                    object_storage_client.put_object(namespace, bucket_name, FILE_NAME, io.open(UPLOAD_FOLDER + FILE_NAME ,'rb'))
                    print("SUCCESS: Uploaded .zip file to Object Storage...")
                except:
                    print("ERROR: Unable to upload to Object Storage: " + FILE_NAME)
                os.remove(UPLOAD_FOLDER + FILE_NAME)

        print("Downloads Folder")
        for dirEntry in os.scandir(app.config['DOWNLOAD_FOLDER']):  # replace temp with download folder
            if dirEntry.name.endswith(".out"):
                FILE_NAME = dirEntry.name
                os.remove(DOWNLOAD_FOLDER + "/" + FILE_NAME)

        print("Begin ADW")
        engine = create_engine(uri)
        conn = engine.connect()
        # begin transaction
        trans = conn.begin()

        for master_dictionary in filevalues:
            try:
                dbName = master_dictionary['DBName']
                ver = master_dictionary['Version']
                rac = master_dictionary['RAC']
                rac_node = master_dictionary["#RAC Nodes"]
                server = master_dictionary['Servers']
                socket = master_dictionary['Sockets']
                cores = master_dictionary['Cores']
                sga = master_dictionary["SGA"]
                pga = master_dictionary["PGA"]
                dbSize = master_dictionary["DBSize(GB)"]
                readWrite = master_dictionary["Reads/Writes"]
                totalReads = master_dictionary["Total Reads"]
                totalWrites = master_dictionary["Total Writes"]
                physMemory = master_dictionary["PHYSICAL_MEMORY_GB"]
                aveOsCpu = master_dictionary["average_os_cpu"]
                aveOsCpuMax = master_dictionary["average_os_cpu_max"]
                maxOsCpuMax = master_dictionary["max_os_cpu_max"]
                email = userName

                alter_statement = "ALTER SESSION SET TIME_ZONE = '-5:0'"
                conn.execute(text(alter_statement))

                
                insert_statement = f" INSERT INTO AWR_REPORT_DATA_06222020 (id, time_uploaded, upload_email, DBName, DB_Version, RAC, RAC_Node_Number, Servers, " \
                               f"Sockets, Cores, SGA, PGA, DBSize, Read_Writes, Total_Reads, Total_Writes, PHYSICAL_MEMORY_GB, average_os_cpu, average_os_cpu_max, max_os_cpu_max) VALUES (" \
                               f"SEQ_AWR_ID.NEXTVAL, CURRENT_TIMESTAMP, '{email}', '{dbName}', '{ver}', '{rac}', '{rac_node}', '{server}', " \
                               f"'{socket}', '{cores}', '{sga}', '{pga}', '{dbSize}', '{readWrite}', '{totalReads}', " \
                               f"'{totalWrites}', '{physMemory}', '{aveOsCpu}', '{aveOsCpuMax}', '{maxOsCpuMax}'  ) "
                conn.execute(text(insert_statement))
                print("Inserting {} values success...".format(master_dictionary['DBName']))
            except:
                print("Unexpected error:", sys.exc_info()[0])
                print("Unexpected error:", sys.exc_info()[1])
        trans.commit()

        print("Process Complete: Closing DB Connection")
        conn.close()
        print("SCRIPT SUCCESSFULLY COMPLETED")
        print(userName)

    except:
            print ("ERRORS while running script - removing .out files from directory")
            for dirEntry in os.scandir(app.config['DOWNLOAD_FOLDER']):  # replace temp with download folder
                if dirEntry.name.endswith(".out"):
                    print ("Removing file: " + dirEntry)
                    os.remove(dirEntry)
            print ("Done removing .out files from directory")


@app.route('/uploads')
def uploaded_file():
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], 'AWR_Report_Data.csv', as_attachment=True)

option = getOptions()
# Set env variables for ADW Connection
os.environ["TNS_ADMIN"] = option["tnsAdmin"]
os.environ["ADW_USER"] = option["adwUser"]
os.environ["ADW_PASSWORD"] = option["adwPassword"]
os.environ["ADW_SID"] = option["adwSID"]

# Establish ADW Connection
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
uri = f'oracle+cx_oracle://{os.environ["ADW_USER"]}:{os.environ["ADW_PASSWORD"]}@{os.environ["ADW_SID"]}'

# configuration for connection to Oracle OCI
config = {
    "user": option["user"],
    "key_file": option["key_file"],
    "fingerprint": option["fingerprint"],
    "tenancy": option["tenancy"],
    "region": option["region"]
}


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

