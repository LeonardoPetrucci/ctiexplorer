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

if __name__ == "__main__":
    #TODO Get CVE-ID from some vulnerability scanner. It will be the input for the program
    cve_list = ["CVE-2014-1266", "CVE-2009-3421"]

    cwe_list = fetch_cwe(cve_list, cve)
    capec_list = []
    for cve_id in cve_list:
        capec_list += fetch_capec(cve_id, cwe_list, capec)
    technique_list = []
    for capec_id in capec_list:
        technique_list += fetch_techniques(capec_id, attack_techniques)
    print(technique_list)
    compatible_groups = []
    compatible_software = []
    group_list = attack_groups.distinct("id",{})
    for group in group_list:
        group_techniques = partner(group, attack_relationships, "attack-pattern")
        if all(item in group_techniques for item in technique_list) or all(item in technique_list for item in group_techniques):
            compatible_groups.append(group)
    if len(compatible_groups) == 1:
        print("Group detected: " + compatible_groups[0])
    else:
        software_pool = []
        for technique in technique_list:
            software_pool += partner(technique, attack_relationships, "tool") + partner(technique, attack_relationships, "malware")
        print(len(software_pool))

