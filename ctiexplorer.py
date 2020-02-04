from mongocti import *
from classification import software_pool_profile, fetch_groups
import cve
import capec
import attack
import sys
import json
def generate_attacker(cve_list):
    capec_list = []
    for cve_id in cve_list:
        capec_list += cve.capec(cve_id)
    
    preliminary_technique_list = []
    for capec_id in capec_list:
        preliminary_technique_list += capec.attack_technique(capec_id)

    software_list = []
    for technique in preliminary_technique_list:
        software_list += attack.relationship_with(technique, "software")
    
    profile = software_pool_profile(software_list)

    full_technique_list = []
    for software in software_list:
        full_technique_list += attack.relationship_with(software, "attack-pattern")
    
    return profile, full_technique_list



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No CVE list to analyze. Please insert at least one CVE ID.\n")
        sys.exit(0)
    
    cve_list = sys.argv[1:]
    
    print('\n-------------------------------CVE-------------------------------')
    for cve_id in cve_list:
        print(cve_id)
    
    profile, technique_list = generate_attacker(cve_list)


    print('\n-------------------ATTACKER POSSIBILE TECHNIQUES-----------------')
    if len(technique_list) < 1:
        print("No techniques found in ATT&CK database.\n")
        sys.exit(0)
        
    else:
        for technique in technique_list:
            print(technique)

        print('\n-----------------------ATTACKER PROFILE--------------------------')
        print(json.dumps(profile, indent=4))

        print('\n------------------------ATTACKER IDENTIFICATION------------------')
        compatible_groups = fetch_groups(technique_list)
        if len(compatible_groups) > 1:
            for group in compatible_groups:
                print(group)
        else:
            print("No groups found in ATT&CK Database for this technique pool.\n")

    print()
    sys.exit(0)