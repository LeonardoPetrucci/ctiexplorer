import os
import requests
import re
from shutil import rmtree
from taxii2client import Server

FEEDS = ["CVE", "CWE", "CAPEC", "MISP", "ATTACK"]

MITRE_STIX = "https://cti-taxii.mitre.org/stix/collections/"
MITRE_TAXII = Server("https://cti-taxii.mitre.org/taxii/")
API_ROOT = MITRE_TAXII.api_roots[0]

NVD_FEED = 'https://nvd.nist.gov/vuln/data-feeds#JSON_FEED'
NVD_REGEX = 'nvdcve-1.1-[0-9]*\.json\.zip'

NVD = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
CWE = 'https://cwe.mitre.org/data/xml/views/'
CAPEC = 'https://capec.mitre.org/data/xml/views/'

CIRCL_API = 'https://cve.circl.lu/api/'

MISP_GALAXY = 'https://raw.githubusercontent.com/MISP/misp-galaxy/master/clusters/'
MISP_THREAT_ACTOR = 'threat-actor.json'

ATTACK_TEACHER = 'https://raw.githubusercontent.com/TravisFSmith/mitre_attack/master/teaching/All.json'

RED = '#fc3b3b'
ORANGE = '#fd8d3c'
YELLOW = '#fce93b'
GREEN = '#31a354'
BLUE = '#3182bd'

def get_NVD_names():
    nvd = requests.get(NVD_FEED)
    filenames = []
    for filename in re.findall(NVD_REGEX,nvd.text):
        filenames.append(filename)
    return filenames

NVD_NAMES = get_NVD_names()
CWE_NAMES = ['1000.xml.zip', '699.xml.zip', '1008.xml.zip']
CAPEC_NAMES = ['1000.xml.zip', '3000.xml.zip']

current_directory = os.path.dirname(__file__)
NVD_PATH = os.path.join(current_directory, "Feeds/NVD/")
CWE_PATH = os.path.join(current_directory, "Feeds/CWE/")
CAPEC_PATH = os.path.join(current_directory, "Feeds/CAPEC/")
MISP_PATH = os.path.join(current_directory, "Feeds/MISP/")

def remove_feeds():
    rmtree(NVD_PATH, ignore_errors=True)
    rmtree(CWE_PATH, ignore_errors=True)
    rmtree(CAPEC_PATH, ignore_errors=True)
    rmtree(MISP_PATH, ignore_errors=True)
    return

def GROUP_URL(attack_group):
    return "https://attack.mitre.org/groups/" + attack_group + "/"