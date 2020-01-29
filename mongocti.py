import requests
import re
import os
import zipfile
import json
import xmltodict
from collections import OrderedDict
from stix2 import TAXIICollectionSource, Filter, AttackPattern, parse
from taxii2client import Server, Collection
from pymongo import MongoClient
import sys

FEEDS = ["CVE", "CWE", "CAPEC", "ATTACK"]

MITRE_STIX = "https://cti-taxii.mitre.org/stix/collections/"
MITRE_TAXII = Server("https://cti-taxii.mitre.org/taxii/")
API_ROOT = MITRE_TAXII.api_roots[0]

NVD_FEED = 'https://nvd.nist.gov/vuln/data-feeds#JSON_FEED'
NVD_REGEX = 'nvdcve-1.1-[0-9]*\.json\.zip'

NVD = 'https://nvd.nist.gov/feeds/json/cve/1.1/'
CWE = 'https://cwe.mitre.org/data/xml/views/'
CAPEC = 'https://capec.mitre.org/data/xml/views/'
CIRCL_API = 'https://cve.circl.lu/api/'

def get_NVD_names():
    nvd = requests.get(NVD_FEED)
    filenames = []
    for filename in re.findall(NVD_REGEX,nvd.text):
        filenames.append(filename)
    return filenames

NVD_NAMES = get_NVD_names()
CWE_NAMES = ['1000.xml.zip', '699.xml.zip', '1008.xml.zip']
CAPEC_NAMES = ['1000.xml.zip', '3000.xml.zip']

#change this, I don't want anything to save locally except the mongodb instance
current_directory = os.path.dirname(__file__)
NVD_PATH = os.path.join(current_directory, "NVD/")
CWE_PATH = os.path.join(current_directory, "CWE/")
CAPEC_PATH = os.path.join(current_directory, "CAPEC/")


def download_file(url, path, filename):
    file_stream = requests.get(url + filename, stream = True)
    with open(path + filename, 'wb') as f:
        for chunk in file_stream:
            f.write(chunk)

def download_all():
    if not os.path.exists(NVD_PATH):
        os.makedirs(NVD_PATH)

    for filename in NVD_NAMES:
        if not os.path.isfile(os.path.join(NVD_PATH, filename)):
            download_file(NVD, NVD_PATH, filename)

    if not os.path.exists(CWE_PATH):
        os.makedirs(CWE_PATH)

    for filename in CWE_NAMES:
        if not os.path.isfile(os.path.join(CWE_PATH, filename)):
            download_file(CWE, CWE_PATH, filename)

    if not os.path.exists(CAPEC_PATH):
        os.makedirs(CAPEC_PATH)

    for filename in CAPEC_NAMES:
        if not os.path.isfile(os.path.join(CAPEC_PATH, filename)):
            download_file(CAPEC, CAPEC_PATH, filename)

def cti_create(collection, client):
    cti = client['cti']

    cve = cti['cve']
    cwe = cti['cwe']
    capec = cti['capec']
    attack_techniques = cti['attack_techniques']
    attack_relationships = cti['attack_relationships']
    attack_groups = cti['attack_groups']
    attack_malware = cti['attack_malware']
    attack_tools = cti['attack_tools']
    attack_mitigations = cti['attack_mitigations']

    try:
        if collection == "CVE":
            files = [f for f in os.listdir(NVD_PATH) if os.path.isfile(os.path.join(NVD_PATH, f))]
            files.sort()
            for file in files:
                archive = zipfile.ZipFile(os.path.join(NVD_PATH, file), 'r')
                jsonfile = archive.open(archive.namelist()[0])
                nvd_dict = json.loads(jsonfile.read())
                for element in nvd_dict['CVE_Items']:
                    cve.insert_one(element)
                jsonfile.close()
            return

        elif collection == "CWE":
            files = [f for f in os.listdir(CWE_PATH) if os.path.isfile(os.path.join(CWE_PATH, f))]
            files.sort()
            for file in files:
                archive = zipfile.ZipFile(os.path.join(CWE_PATH, file), 'r')
                jsonfile = archive.open(archive.namelist()[0])
                cwe_dict = xmltodict.parse(jsonfile.read())
                cwe_list = cwe_dict['Weakness_Catalog']['Weaknesses']['Weakness']
                for element in cwe_list:
                    cwe.insert_one(json.loads(json.dumps(element).replace("@", "")))
                jsonfile.close()
            return

        elif collection == "CAPEC":
            files = [f for f in os.listdir(CAPEC_PATH) if os.path.isfile(os.path.join(CAPEC_PATH, f))]
            files.sort()
            for file in files:
                archive = zipfile.ZipFile(os.path.join(CAPEC_PATH, file), 'r')
                jsonfile = archive.open(archive.namelist()[0])
                capec_dict = xmltodict.parse(jsonfile.read())
                capec_list = capec_dict['Attack_Pattern_Catalog']['Attack_Patterns']['Attack_Pattern']
                for element in capec_list:
                    capec.insert_one(json.loads(json.dumps(element).replace("@", "")))
                jsonfile.close()
            return

        elif collection == "ATTACK":

            attack_id = {}
            for collection in API_ROOT.collections:
                attack_id[collection.title] = collection.id

            attack = {}
            enterprise_attack = Collection(MITRE_STIX + attack_id["Enterprise ATT&CK"])
            pre_attack = Collection(MITRE_STIX + attack_id["PRE-ATT&CK"])
            mobile_attack = Collection(MITRE_STIX + attack_id["Mobile ATT&CK"])

            enterprise_attack_source = TAXIICollectionSource(enterprise_attack)
            pre_attack_source = TAXIICollectionSource(pre_attack)
            mobile_attack_source = TAXIICollectionSource(mobile_attack)

            filter_objs = {"techniques": Filter("type", "=", "attack-pattern"),
                "mitigations": Filter("type", "=", "course-of-action"),
                "groups": Filter("type", "=", "intrusion-set"),
                "malware": Filter("type", "=", "malware"),
                "tools": Filter("type", "=", "tool"),
                "relationships": Filter("type", "=", "relationship")
            }

            for key in filter_objs:
                attack[key] = []
                try:
                    attack[key] += enterprise_attack_source.query(filter_objs[key])
                except:
                    pass
                try:
                    attack[key] += pre_attack_source.query(filter_objs[key])
                except:
                    pass
                try:
                    attack[key] += mobile_attack_source.query(filter_objs[key])
                except:
                    pass

            for entity in attack["relationships"]:
                attack_relationships.insert_one(dict(entity))

            for entity in attack["techniques"]:
                attack_techniques.insert_one(dict(entity))

            for entity in attack["groups"]:
                attack_groups.insert_one(dict(entity))

            for entity in attack["malware"]:
                attack_malware.insert_one(dict(entity))

            for entity in attack["tools"]:
                attack_tools.insert_one(dict(entity))

            for entity in attack["mitigations"]:
                attack_mitigations.insert_one(dict(entity))

            return
        else:
            print("Collection type not set")
            return
    except:
        print("OOPS! An error occured. Wiping CTI database...")
        client.drop_database('cti')
        sys.exit("CTI database has been dropped, please create a new instance.")


download_all()

try:
    cti_client = MongoClient('localhost', 27017)
except:
    sys.exit("Cannot connect to MongoDB.")

if "cti" not in cti_client.list_database_names():
    print("No CTI Database instance found. Creating...")
    for feed in FEEDS:
        cti_create(feed, cti_client)

cti = cti_client['cti']

cve = cti['cve']
cwe = cti['cwe']
capec = cti['capec']
attack_techniques = cti['attack_techniques']
attack_relationships = cti['attack_relationships']
attack_groups = cti['attack_groups']
attack_malware = cti['attack_malware']
attack_tools = cti['attack_tools']
attack_mitigations = cti['attack_mitigations']

