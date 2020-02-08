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
from pathlib import Path

RSS_FEED = "https://www.us-cert.gov/ncas/analysis-reports.xml"
connect_str = "DefaultEndpointsProtocol=https;AccountName=sathomasdefise;AccountKey=cZaRJkmH6vYAFV62Um0kvEdKRlAUm3psDfvDGarVbOgn4DawTFTZUFeu9OaQEeaxeFkQ7z82Fj962soVzSeB4w==;EndpointSuffix=core.windows.net"


def create_yara_file(report_id, yara):
    folder_path = os.path.join(os.getcwd(),report_id)
    file_path = os.path.join(folder_path,yara["name"])
    Path(folder_path).mkdir(parents=True, exist_ok=True)
    yara_file = open(file_path,'w')
    yara_file.write(yara["rule"])
    yara_file.close()

def upload_yara_file_az_sa(blob_service_client, report_id, filename):
    
    upload_file_path = os.path.join(os.getcwd(), report_id, filename)

    # Create a blob client using the local file name as the name for the blob
    blob_client = blob_service_client.get_blob_client(container="us-cert-stix-reports", blob=filename)

    print("\nUploading to Azure Storage as blob:\n\t" + filename)

    # Upload the created file
    with open(upload_file_path, "rb") as data:
        blob_client.upload_blob(data)


def upload_file_az_sa(blob_service_client, filename):
    
    upload_file_path = os.path.join(os.getcwd(),filename)

    # Create a blob client using the local file name as the name for the blob
    blob_client = blob_service_client.get_blob_client(container="us-cert-stix-reports", blob=filename)

    print("\nUploading to Azure Storage as blob:\n\t" + filename)

    # Upload the created file
    with open(upload_file_path, "rb") as data:
        blob_client.upload_blob(data)
        
def upload_yara_az_sa(report_id, yara_rule_name):
    try:
        
        blob_service_client = BlobServiceClient.from_connection_string(connect_str)
         # Instantiate a ContainerClient
        container_client = blob_service_client.get_container_client("us-cert-stix-reports"+"//"+report_id)
        blob_list = container_client.list_blobs()
        if blob_list.by_page() is None:
            print("Nothing in the container")
            upload_yara_file_az_sa(blob_service_client,report_id,yara_rule_name)
        else: 
            for blob in blob_list:
                if blob.name == yara_rule_name:
                    print("File already present within the container")
                else:
                    print("File not present")
                    upload_yara_file_az_sa(blob_service_client,report_id,yara_rule_name)
    except Exception as error:
        print("Unexpected Error : ", error)    

def check_file_processed_az_sa(filename):

    # Instantiate a BlobServiceClient using a connection string
    try:
        blob_service_client = BlobServiceClient.from_connection_string(connect_str)

        # Instantiate a ContainerClient
        container_client = blob_service_client.get_container_client("us-cert-stix-reports")

        blob_list = container_client.list_blobs()
        if blob_list.by_page().results_per_page is None:
            upload_file_az_sa(blob_service_client,filename)
        else: 
            for blob in blob_list:
                if blob.name == filename:
                    print("File already present within the container")
                else:
                    upload_file_az_sa(blob_service_client,filename)
    except Exception as error:
        print("Unexpected Error : ", error)


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

def parse_STIX(stixurl, title):
    print(stixurl.decode("ascii"))
    try:
        r = requests.get(stixurl)
        data = r.text
    except Exception as error:
        print("Unexpected Error : ", error)

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
    
        elif raw_observable.get('id').startswith("NCCIC:WhoisEntry"):
            pass
        
        elif raw_observable.get('id').startswith("NCCIC:Port"):
            pass
        
        if parsed_observable["usable"]:
            pass
            # print(parsed_observable)

    for raw_indicator in soup.findAll(['stix:indicator']):
        yara = {}
        raw_indicator_title = raw_indicator.find('indicator:title')
        raw_indicator_title_string = str(raw_indicator_title)
        if ".yara" in raw_indicator_title_string:
            yara["name"] = raw_indicator_title.get_text().split(":", 1)[0]
            raw_indicator_yara_rule = raw_indicator.find('yaratm:rule')
            yara["rule"] = raw_indicator_yara_rule.get_text()
            
            yara_folder = "MAR-"+stixurl.decode("ascii").split("MAR-", 1)[1]
            yara_folder = yara_folder.replace(".stix.xml","")
            
            print(yara_folder)
            create_yara_file(yara_folder, yara)
            upload_yara_az_sa(yara_folder,yara["name"])
        

def processUS_CertRSS():
    feed = feedparser.parse(RSS_FEED)
    for entry in feed.entries:
        
        stixFile = (re.search(b"(https:\/\/www.us-cert.gov\/sites)(.*)stix.xml",entry.description.encode("utf8")))
        if stixFile is not None:
            stix_xml_url = stixFile.group(0)
            title = entry.title
            parse_STIX(stix_xml_url,title)
            
            
def main():
    processUS_CertRSS()


main()
# check_file_processed_az_sa("MAR-10158513.r1.v1.stix.xml")



"""
As Microsoft Defender ATP is limited to ... entries, I will only 
For Azure Sentinel, I will give both SH256 and SSDEEP.

"""