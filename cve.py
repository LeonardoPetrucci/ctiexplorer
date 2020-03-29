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

def score(cve, version=2):
    try:
        if version == 3:
            cvss_3 = cve_db.distinct("impact.baseMetricV3", {"cve.CVE_data_meta.ID": cve})
            return cvss_3[0]
        else:    
            cvss_2 = cve_db.distinct("impact.baseMetricV2", {"cve.CVE_data_meta.ID": cve})
            return cvss_2[0]
    except:
        return {}

