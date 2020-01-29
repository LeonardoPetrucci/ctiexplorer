import json
import requests
from mongocti import *

def fetch_techniques(attack_pattern_id, attack_technique_collection):
    capec_id = "CAPEC-" + attack_pattern_id
    techniques = []
    for technique in attack_technique_collection.distinct("id", {"external_references.external_id": capec_id}):
        techniques.append(technique)
    return techniques

def partner(attack_entity_id, attack_relationships, collection_type):
    partners = []
    for entity in attack_relationships.find({'$or': [{'target_ref': attack_entity_id}, {'source_ref': attack_entity_id}]}):
        target = entity['target_ref']
        source = entity['source_ref']
        if attack_entity_id in target and collection_type in source:
            partners.append(source)
        elif attack_entity_id in source and collection_type in target:
            partners.append(target)
    return partners

def fetch_cwe(vuln_list, cve_db):
    cwe_list = []
    for vuln_id in vuln_list:
        cwe_id = cve_db.distinct("cve.problemtype.problemtype_data.description.value", {"cve.CVE_data_meta.ID":vuln_id})
        cwe_list.append(cwe_id[0].split('-')[1])
    return cwe_list

def fetch_capec(cve_id, cwe_list, capec_db):
    capec_list = []
    attack_patterns = json.loads(requests.get(CIRCL_API + "cve/" + cve_id).text)['capec']
    for attack_pattern in attack_patterns:
        capec_id = attack_pattern['id']
        capec_cwe = capec_db.distinct("Related_Weaknesses.Related_Weakness.CWE_ID", {"ID":capec_id})
        for cwe_id in capec_cwe:
            if cwe_id in cwe_list:
                capec_list.append(capec_id)
                break
    return capec_list

    