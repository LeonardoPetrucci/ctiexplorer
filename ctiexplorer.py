from mongocti import *
from data_manager import *

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
        group_techniques = fetch_partner(group, attack_relationships, "attack-pattern")
        if all(item in group_techniques for item in technique_list) or all(item in technique_list for item in group_techniques):
            compatible_groups.append(group)
    if len(compatible_groups) == 1:
        print("Group detected: " + compatible_groups[0])
    else:
        software_pool = []
        for technique in technique_list:
            software_pool += fetch_partner(technique, attack_relationships, "tool") + fetch_partner(technique, attack_relationships, "malware")
        print(len(software_pool))

