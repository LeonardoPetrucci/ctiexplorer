import json
import requests
from mongocti import *
from paths import CIRCL_API

def cwe(cve):
    cwe_list = []
    
    try:
        cwe_list.append(json.loads(requests.get(CIRCL_API + "cve/" + cve).text)['cwe'].split("-")[1])
    except:
        print('CIRCL: ' + str(cve) + ' has no related CWE IDs.')
    
    return cwe_list

def capec(cve):
    capec_list = []
    try:
        attack_patterns = json.loads(requests.get(CIRCL_API + "cve/" + cve).text)['capec']
    except:
        print('CIRCL: ' + str(cve) + ' has no related CAPEC IDs.')
        return capec_list
        
    for attack_pattern in attack_patterns:
        capec_id = attack_pattern['id']
        capec_list.append(capec_id)
    
    return capec_list

def cvss_severity(cve):
    try:
        return cve_db.distinct("impact.baseMetricV2.severity", {"cve.CVE_data_meta.ID": cve})
    except:
        return []

def cvss_exscore(cve):
    try:
        return cve_db.distinct("impact.baseMetricV2.exploitabilityScore", {"cve.CVE_data_meta.ID": cve})
    except:
        return []

def cvss_impactscore(cve):
    try:
        return cve_db.distinct("impact.baseMetricV2.impactScore", {"cve.CVE_data_meta.ID": cve})
    except:
        return []

def cvss_vector(cve):
    try:
        return cve_db.distinct("impact.baseMetricV2.cvssV2.vectorString", {"cve.CVE_data_meta.ID": cve})
    except:
        return []

def cvss_basescore(cve):
    
    try:
        return cve_db.distinct("impact.baseMetricV2.cvssV2.baseScore", {"cve.CVE_data_meta.ID": cve})
    except:
        return []