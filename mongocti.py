import requests
import re
import os
import zipfile
import json
import xmltodict
import sys
import datetime

from math import modf
from paths import *
from collections import OrderedDict
from stix2 import TAXIICollectionSource, Filter, AttackPattern, parse
from taxii2client import Server, Collection
from pymongo import MongoClient

from classification import threat_actor_category

OWASP = float(9/5)

__all__ = ['cve_db', 'cwe_db', 'capec_db', 'techniques_db', 'relationships_db', 'groups_db', 'software_db', 'mitigations_db', 'threat_actors_db']


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
    attack_software = cti['attack_software']
    attack_mitigations = cti['attack_mitigations']
    misp_threat_actor = cti['misp_threat_actor']

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
        technique_helper = []
        software_helper = []

        attack_id = {}
        for collection in API_ROOT.collections:
            attack_id[collection.title] = collection.id

        attack_collection = {}
        enterprise_attack = Collection(MITRE_STIX + attack_id["Enterprise ATT&CK"])
        pre_attack = Collection(MITRE_STIX + attack_id["PRE-ATT&CK"])

        enterprise_attack_source = TAXIICollectionSource(enterprise_attack)
        pre_attack_source = TAXIICollectionSource(pre_attack)

        teacher = dict((requests.get(ATTACK_TEACHER).json()))
        teacher_dict = {}
        for technique in teacher['techniques']:
            if technique["color"] == RED:
                teacher_dict[technique["techniqueID"]] = '5'
            elif technique["color"] == ORANGE:
                teacher_dict[technique["techniqueID"]] = '4'
            elif technique["color"] == YELLOW:
                teacher_dict[technique["techniqueID"]] = '3'
            elif technique["color"] == GREEN:
                teacher_dict[technique["techniqueID"]] = '2'
            elif technique["color"] == BLUE:
                teacher_dict[technique["techniqueID"]] = '1'
            else:
                teacher_dict[technique["techniqueID"]] = 'Unknown'

        filter_objs = {"techniques": Filter("type", "=", "attack-pattern"),
            "mitigations": Filter("type", "=", "course-of-action"),
            "groups": Filter("type", "=", "intrusion-set"),
            "malware": Filter("type", "=", "malware"),
            "tools": Filter("type", "=", "tool"),
            "relationships": Filter("type", "=", "relationship")
        }

        for key in filter_objs:
            attack_collection[key] = []
            try:
                attack_collection[key] += enterprise_attack_source.query(filter_objs[key])
            except:
                pass
            try:
                attack_collection[key] += pre_attack_source.query(filter_objs[key])
            except:
                pass

        for entity in attack_collection["relationships"]:
            attack_relationships.insert_one(dict(entity))

        for entity in attack_collection["techniques"]:
            dict_entity = dict(entity)
            for references in dict_entity['external_references']:
                if 'attack' in references['source_name']:
                    attack_id = references['external_id']
                    if attack_id in teacher_dict.keys():
                        dict_entity['level'] = teacher_dict[attack_id]
                    else:
                        dict_entity['level'] = 'Unknown'
                    technique_helper.append(dict_entity)
                    attack_techniques.insert_one(dict_entity)


        for entity in attack_collection["malware"]:
            dict_entity = dict(entity)
            sw_id = dict_entity['id']
            
            techniques = []
            measured_techniques = 0
            ttp_score_sum = 0

            for relationship in attack_collection["relationships"]:
                dict_rel = dict(relationship)

                if dict_rel['source_ref'] == sw_id:
                    if 'attack-pattern' in dict_rel['target_ref']:
                        techniques.append(dict_rel['target_ref'])

                elif dict_rel['target_ref'] == sw_id:
                    if 'attack-pattern' in dict_rel['source_ref']:
                        techniques.append(dict_rel['source_ref'])

            for ttp_id in techniques:
                for technique in technique_helper:
                    if technique['id'] == ttp_id and technique['level'] != "Unknown":
                        measured_techniques += 1
                        ttp_score_sum += int(technique['level'])

            if measured_techniques == 0:
                dict_entity['score'] = 'Unknown'
            else:
                dict_entity['score'] = round(ttp_score_sum / measured_techniques, 2)

            software_helper.append(dict_entity)
            attack_software.insert_one(dict_entity)

        for entity in attack_collection["tools"]:
            dict_entity = dict(entity)
            sw_id = dict_entity['id']
            
            techniques = []
            measured_techniques = 0
            ttp_score_sum = 0

            for relationship in attack_collection["relationships"]:
                dict_rel = dict(relationship)

                if dict_rel['source_ref'] == sw_id:
                    if 'attack-pattern' in dict_rel['target_ref']:
                        techniques.append(dict_rel['target_ref'])

                elif dict_rel['target_ref'] == sw_id:
                    if 'attack-pattern' in dict_rel['source_ref']:
                        techniques.append(dict_rel['source_ref'])


            for ttp_id in techniques:
                for technique in technique_helper:
                    if technique['id'] == ttp_id and technique['level'] != "Unknown":
                        measured_techniques += 1
                        ttp_score_sum += int(technique['level'])

            if measured_techniques == 0:
                dict_entity['score'] = 'Unknown'
            else:
                dict_entity['score'] = round(ttp_score_sum / measured_techniques, 2)

            software_helper.append(dict_entity)
            attack_software.insert_one(dict_entity)


        for entity in attack_collection["groups"]:
            dict_entity = dict(entity)
            gr_id = dict_entity['id']

            measured_techniques = 0
            ttp_score_sum = 0
            used_techniques = []

            measured_software = 0
            sw_score_sum = 0
            used_software = []


            for relationship in attack_collection["relationships"]:
                dict_rel = dict(relationship)

                if dict_rel['source_ref'] == gr_id:
                    if 'attack-pattern' in dict_rel['target_ref']:
                        used_techniques.append(dict_rel['target_ref'])

                elif dict_rel['target_ref'] == gr_id:
                    if 'attack-pattern' in dict_rel['source_ref']:
                        used_techniques.append(dict_rel['source_ref'])


            for ttp_id in used_techniques:
                for technique in technique_helper:
                    if technique['id'] == ttp_id and technique['level'] != "Unknown":
                        measured_techniques += 1
                        ttp_score_sum += float(technique['level'])

            if measured_techniques == 0:
                dict_entity['skill_level'] = 'Unknown'
            else:
                dict_entity['skill_level'] = float(ttp_score_sum / measured_techniques)

            for relationship in attack_collection["relationships"]:
                dict_rel = dict(relationship)

                if dict_rel['source_ref'] == sw_id:
                    if 'malware' in dict_rel['target_ref'] or 'tool' in dict_rel['target_ref']:
                        used_software.append(dict_rel['target_ref'])

                elif dict_rel['target_ref'] == sw_id:
                    if 'malware' in dict_rel['target_ref'] or 'tool' in dict_rel['target_ref']:
                        used_software.append(dict_rel['source_ref'])


            for sw_id in used_software:
                for software in software_helper:
                    if software['id'] == sw_id and software['score'] != "Unknown":
                        measured_software += 1
                        sw_score_sum += float(software['score'])

            if measured_software == 0:
                dict_entity['opportunity'] = 'Unknown'
            else:
                dict_entity['opportunity'] = float(sw_score_sum / measured_software)

            if (dict_entity['skill_level'] == "Unknown") and (dict_entity['opportunity'] != 'Unknown'):
                dict_entity['skill_level'] = dict_entity['opportunity']

            if (dict_entity['opportunity'] == "Unknown") and (dict_entity['skill_level'] != 'Unknown'):
                dict_entity['opportunity'] = dict_entity['skill_level']

            if dict_entity['opportunity'] != 'Unknown' and dict_entity['skill_level'] != 'Unknown':
                dict_entity['skill_level'] = int(modf(OWASP * dict_entity['skill_level'])[1])
                dict_entity['opportunity'] = int(modf(OWASP * dict_entity['opportunity'])[1])
            
            stix_group_id = dict_entity['id'].split("--")[1]
            attack_group_id = None
            for external_reference in dict_entity['external_references']:
                if 'attack' in external_reference['source_name']:
                    attack_group_id = external_reference['external_id']
                    break


            threat_actors = []
            try:
                misp_list = misp_threat_actor.distinct('uuid', {"meta.refs": GROUP_URL(attack_group_id)}) + misp_threat_actor.distinct('uuid', {"related.dest-uuid": stix_group_id})
                for threat_actor in misp_list:
                    if threat_actor not in threat_actors:
                        threat_actors.append(threat_actor)
            except:
                pass

            motive_list = []
            size_list = []

            for threat_actor in threat_actors:
                threat_actor_list = misp_threat_actor.find({'uuid':threat_actor})
                for threat_actor_dict in threat_actor_list:

                    motive_list.append(int(threat_actor_dict['motive']))
                    size_list.append(int(threat_actor_dict['size']))
            
            if len(motive_list) > 0:
                dict_entity['motive'] = str(sum(motive_list)/len(motive_list))
            else: 
                dict_entity['motive'] = '0'
            if dict_entity['motive'] == '0':
                dict_entity['motive'] = 'Unknown'

            
            if len(size_list) > 0:
                dict_entity['size'] = str(sum(size_list)/len(size_list))
            else: 
                dict_entity['size'] = '0'
            if dict_entity['size'] == '0':
                dict_entity['size'] = 'Unknown'

            attack_groups.insert_one(dict_entity)


        for entity in attack_collection["mitigations"]:
            attack_mitigations.insert_one(dict(entity))

        return
     
    elif collection == "MISP":
        with open(os.path.join(MISP_PATH, MISP_THREAT_ACTOR), 'r', encoding="UTF-8") as misp_file:
            threat_actors = json.loads(misp_file.read())

            for threat_actor in threat_actors['values']:
                dict_threat_actor = threat_actor_category(dict(threat_actor))
                misp_threat_actor.insert_one(dict_threat_actor)

            misp_file.close()
    
    else:
        print("Collection type not set")
        return


try:
    cti_client = MongoClient('localhost', 27017)
except:
    sys.exit("Cannot connect to MongoDB.")


if "cti" not in cti_client.list_database_names():
    print("No CTI Database instance found.")
    print('Creating CTI Database instance...')
    download_all()
    for feed in FEEDS:
        cti_create(feed, cti_client)

elif len(sys.argv) > 1 and (sys.argv[1] == '-U' or sys.argv[1] == '--update'):
    print('Updating CTI Database instance...')
    remove_feeds()
    cti_client.drop_database('cti')
    download_all()
    for feed in FEEDS:
        cti_create(feed, cti_client)

elif len(sys.argv) > 1 and (sys.argv[1] == '-W' or sys.argv[1] == '--wipe'):
    print('Wiping CTI Database instance...')
    remove_feeds()
    cti_client.drop_database('cti')
    print("Done.\n")
    sys.exit(0)

else:
    pass

cti = cti_client['cti']

cve_db = cti['cve']
cwe_db = cti['cwe']
capec_db = cti['capec']
techniques_db = cti['attack_techniques']
relationships_db = cti['attack_relationships']
groups_db = cti['attack_groups']
software_db = cti['attack_software']
mitigations_db = cti['attack_mitigations']
threat_actors_db = cti['misp_threat_actor']

print("CTI Database instance ready.\n")