import requests
import re
import os
import zipfile
import json
import xmltodict
import sys

from paths import *
from collections import OrderedDict
from stix2 import TAXIICollectionSource, Filter, AttackPattern, parse
from taxii2client import Server, Collection
from pymongo import MongoClient

__all__ = ['cve_db', 'cwe_db', 'capec_db', 'techniques_db', 'relationships_db', 'groups_db', 'malware_db', 'tools_db', 'mitigations_db', 'threat_actors_db']


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

    if not os.path.exists(MISP_PATH):
        os.makedirs(MISP_PATH)

    if not os.path.isfile(os.path.join(MISP_PATH, MISP_THREAT_ACTOR)):
        download_file(MISP_GALAXY, MISP_PATH, MISP_THREAT_ACTOR)

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
    misp_threat_actor = cti['misp_threat_actor']

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
        
        elif collection == "MISP":
            with open(os.path.join(MISP_PATH, MISP_THREAT_ACTOR), 'r', encoding="UTF-8") as misp_file:
                threat_actors = json.loads(misp_file.read())
                for threat_actor in threat_actors['values']:
                    misp_threat_actor.insert_one(dict(threat_actor))
                misp_file.close()
        
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

cve_db = cti['cve']
cwe_db = cti['cwe']
capec_db = cti['capec']
techniques_db = cti['attack_techniques']
relationships_db = cti['attack_relationships']
groups_db = cti['attack_groups']
malware_db = cti['attack_malware']
tools_db = cti['attack_tools']
mitigations_db = cti['attack_mitigations']
threat_actors_db = cti['misp_threat_actor']

