#!/usr/bin/python


# https://github.com/tiran/defusedxml#python-xml-libraries
# The defusedxml package (defusedxml on PyPI) contains several Python-only workarounds and fixes for denial of service and other vulnerabilities in Python's XML libraries.
import re
import os
import sys
import requests
import urllib
import feedparser 
from bs4 import BeautifulSoup
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import json

RSS_FEED = "https://www.us-cert.gov/ncas/analysis-reports.xml"


def upload_file_az_sa(filename, az_blob_conn_string, az_sa_container):
    
    try:
        blob_service_client = BlobServiceClient.from_connection_string(az_blob_conn_string)

        upload_file_path = os.path.join(os.getcwd(),filename)

        # Create a blob client using the local file name as the name for the blob
        blob_client = blob_service_client.get_blob_client(container=az_sa_container, blob=filename)

        print("\nUploading to Azure Storage as blob:\n\t" + filename)

        # Upload the created file
        with open(upload_file_path, "rb") as data:
            blob_client.upload_blob(data)
    except Exception as error:
        print("Unexpected Error : ", error)

def download_xml_file(stix_file_url, filename):
    try:
        response = requests.get(stix_file_url)
        #data = response.text
        open(filename,'wb').write(response.content)

    except Exception as error:
        print("Unexpected Error : ", error)
        
        
def check_file_already_in_az_sa(filename, az_blob_conn_string, az_sa_container):

    # Instantiate a BlobServiceClient using a connection string
    try:
        blob_service_client = BlobServiceClient.from_connection_string(az_blob_conn_string)

        # Instantiate a ContainerClient
        container_client = blob_service_client.get_container_client(az_sa_container)

        blob_list = container_client.list_blobs()
        
        # If Blob list is empty
        if blob_list.by_page().results_per_page is None:
            return (False)
        else: 
            for blob in blob_list:
                if blob.name == filename:
                    return (True)
                else:
                    return (False)
    except Exception as error:
        print("Unexpected Error : ", error)
        return (False)


def find_hashing_algo(hash, obs):
    if len(hash) == 64:
        obs["SHA256"] = hash
    if len(hash) == 128:
        obs["SHA512"] = hash
    else:
        obs["SSDEEP"] = hash
    return obs


def initilize_observable(metadata):
    obs = {}
    obs["usable"] = False
    obs["tlpLevel"] = "white"
    obs["lastReportedDateTime"] = metadata["lastReportedDateTime"]
    return obs

def parse_ip_address_observable(raw_observable, parsed_observable):
    parsed_observable["usable"] = True
    parsed_observable["Type"] = "IP"
    if raw_observable.contents[1].name == "cybox:properties":
        IP = raw_observable.contents[1].get_text()
        parsed_observable["networkDestinationIPv4"] = IP.replace("\n","")
    return (parsed_observable)

def parse_uri_observable(raw_observable,parsed_observable):
    parsed_observable["usable"] = True
    uri_type = raw_observable.find("cybox:properties")
    if uri_type["type"] == "URL":
        parsed_observable["Type"]="url"
        parsed_observable["url"] = raw_observable.find("uriobj:value").get_text()
    
    elif uri_type["type"] == "Domain Name":
        parsed_observable["Type"]= "Domain Name"
        parsed_observable["domainName"] = raw_observable.find("uriobj:value").get_text()
        
    return (parsed_observable)

def parse_win_exec_observable(raw_observable, parsed_observable):
    parsed_observable["usable"] = True
    parsed_observable["Type"] = raw_observable.get('id')

    #if raw_observable.contents[1].name == "cybox:properties":
    for file_properties in raw_observable.contents[1].descendants:
        file_properties_string = str(file_properties)
        if "fileobj:file_name" in file_properties_string:
            parsed_observable["fileName"] = file_properties.get_text()

        elif "fileobj:size_in_bytes" in file_properties_string:
            # Size of the file in bytes.
            parsed_observable["fileSize"] = int(file_properties.get_text())

        elif "fileobj:file_format" in file_properties_string:
            # Text description of the type of file. 
            # For example, “Word Document” or “Binary”.
            parsed_observable["fileType"] = file_properties.get_text()

        if "cyboxcommon:hash" in file_properties_string:
            for hashes in file_properties.descendants:

                if hashes.name == "cyboxcommon:type":
                    for child3 in hashes.children:
                        # We only keep:
                        # SH256: Used by Microsoft Defender ATP 
                        # SSDEEP: Used to perform Threat Hunting
                        if child3 in ("MD5","SHA1"):
                            break

                if hashes!=None and hashes.name=="cyboxcommon:simple_hash_value":
                    # Hash Value
                    # I don't want the MD5
                    if len(hashes.get_text()) <= 40:
                        break
                    else:
                        parsed_observable = find_hashing_algo(hashes.get_text(),
                                                              parsed_observable)
                        
    return (parsed_observable)

def parse_STIX(stix_file_filename, title):
    try:
        with open(stix_file_filename, 'r', encoding="utf8") as file:
            data = file.read()
        
        parsed_observables = []

        soup = BeautifulSoup(data, 'html.parser')
        # Remove the TTPs part
        soup.find('stix:ttps').decompose()

        # Removing both "WinExecutableFileObj:Headers" and "WinExecutableFileObj:Sections"
        soup.find("winexecutablefileobj:headers").decompose()
        soup.find("winexecutablefileobj:sections").decompose()

        timecreated = soup.find("stixcommon:time").get_text().replace("\n","")
        metadata = {}
        metadata["lastReportedDateTime"] = timecreated

        for raw_observable in soup.findAll(['cybox:observable',
                                        'cybox:object']):
            parsed_observable = initilize_observable(metadata)
            parsed_observable["description"] = title
            
            # Windows Executable
            if raw_observable.get('id').startswith("NCCIC:WinExecutableFile"):
                parsed_observable = parse_win_exec_observable(raw_observable,parsed_observable)

            # IP addresses
            elif raw_observable.get('id').startswith("NCCIC:Address"):
                parsed_observable = parse_ip_address_observable(raw_observable,parsed_observable)
            
            elif raw_observable.get('id').startswith("NCCIC:WhoisEntry"):
                pass
            
            elif raw_observable.get('id').startswith("NCCIC:URI"):
                parsed_observable = parse_uri_observable(raw_observable,parsed_observable)
            
            elif raw_observable.get('id').startswith("NCCIC:Port"):
                pass
            
            elif raw_observable.get('id').startswith("NCCIC:Mutex"):
                pass
            
            if parsed_observable["usable"]:
                parsed_observables.append(parsed_observable)

        return(parsed_observables)
    except Exception as error:
        print("Unexpected Error : ", error)
        return (None)

def convert_observable_to_json(parsed_observables):
    for observables in parsed_observables:
        print (observables)
    return (parsed_observables)

def processUS_CertRSS():
    az_blob_conn_string = os.environ['CUSTOMCONNSTR_blob_storage']
    az_sa_container = os.environ['AZURE', 'AZURE_STORAGEACCOUNT_CONTAINER'']
    
    return_observables = {}
    return_observables["count"] = 0
    return_observables["results"] = []
    
    try:
        feed = feedparser.parse(RSS_FEED)
        for entry in feed.entries:
            # Get the XML which follows the following convention:
            # https://www.us-cert.gov/sites/default/files/publications/MAR-XXXXXXXXXX.stix.xml
            stix_file_url = (re.search(b"(https:\/\/www.us-cert.gov\/sites)(.*)stix.xml",entry.description.encode("utf8")))
            if stix_file_url is not None:
                stix_file_url = stix_file_url.group(0)
                title = entry.title
                stix_file_url_str = stix_file_url.decode("utf-8")
                stix_file_filename = stix_file_url_str.split("publications/",1)[1]
                if not check_file_already_in_az_sa(stix_file_filename,az_blob_conn_string,az_sa_container):
                    download_xml_file(stix_file_url, stix_file_filename)
                    #upload_file_az_sa(stix_file_filename, az_blob_conn_string, az_sa_container)
                    parsed_observables = parse_STIX(stix_file_filename,title)
                    if parsed_observables is not None:
                        return_observables["count"]+=len(parsed_observables)
                        return_observables["results"].append(parsed_observables)
        json_data = json.dumps(return_observables)
        r = requests.post('https://prod-126.westeurope.logic.azure.com:443/workflows/8ce1b4156a7b4142b2ab170bb5d07410/triggers/manual/paths/invoke?api-version=2016-10-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=KJnLT4rOZ7u6wZqv-tEoX_0W3TMjNKYig8ExYdY-v5U', json=json_data)
        print (r.status_code)
                
    except Exception as error:
        print("Unexpected Error : ", error)            
            
def process():
    processUS_CertRSS()


# check_file_processed_az_sa("MAR-10158513.r1.v1.stix.xml")



"""
As Microsoft Defender ATP is limited to ... entries, I will only 
For Azure Sentinel, I will give both SH256 and SSDEEP.

"""