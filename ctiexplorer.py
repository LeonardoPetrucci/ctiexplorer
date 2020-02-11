import cve
import capec
import attack
import sys
import json

from py2neo import Graph, Node, Relationship, NodeMatcher
from mongocti import *
from classification import software_pool_profile, fetch_groups

uri = "bolt://localhost:7687"
user = "neo4j"
password = "cti"

def cti_graph(cve_list, capec_list, preliminary_technique_list, software_list, full_technique_list):
    g = Graph(uri=uri, user=user, password=password)
    matcher = NodeMatcher(g)
    g.delete_all()
    tx = g.begin()

    
    for cve_id in cve_list:
        cve_node = Node("CVE", name=cve_id)
        tx.create(cve_node)
    
    for capec_id in capec_list:
        capec_node = Node("CAPEC", name=capec_id)
        tx.create(capec_node)

    for preliminary_technique in preliminary_technique_list:
        preliminary_technique_node = Node("PRELIMINARY_TECHNIQUE", name=preliminary_technique)
        tx.create(preliminary_technique_node)
    
    for software in software_list:
        sofware_node = Node("SOFTWARE", name=software)
        tx.create(sofware_node)

    for technique in full_technique_list:
        technique_node = Node("TECHNIQUE", name=technique)
        tx.create(technique_node)

    tx.commit()
    tx = g.begin()

    for cve_id in cve_list:
        cve_node = matcher.match("CVE").where("_.name =~ '" + cve_id + "'").first()
        for capec_id in cve.capec(cve_id):
            capec_node = matcher.match("CAPEC").where("_.name =~ '" + capec_id + "'").first()
            cve_capec = Relationship(cve_node, "RELATED", capec_node)
            tx.merge(cve_capec, "RELATED", "name")

    for capec_id in capec_list:
        capec_node = matcher.match("CAPEC").where("_.name =~ '" + capec_id + "'").first()
        for preliminary_technique in capec.attack_technique(capec_id):
            preliminary_technique_node = matcher.match("PRELIMINARY_TECHNIQUE").where("_.name =~ '" + preliminary_technique + "'").first()
            capec_preliminary_technique = Relationship(capec_node, "RELATED", preliminary_technique_node)
            tx.merge(capec_preliminary_technique, "RELATED", "name")
    
    for preliminary_technique in preliminary_technique_list:
        preliminary_technique_node = matcher.match("PRELIMINARY_TECHNIQUE").where("_.name =~ '" + preliminary_technique + "'").first()
        for software in attack.relationship_with(preliminary_technique, "software"):
            software_node = matcher.match("SOFTWARE").where("_.name =~ '" + software + "'").first()
            preliminary_technique_software = Relationship(preliminary_technique_node, "RELATED", software_node)
            tx.merge(preliminary_technique_software)

    for software in software_list:
        software_node = matcher.match("SOFTWARE").where("_.name =~ '" + software + "'").first()
        for technique in attack.relationship_with(software, "attack-pattern"):
            technique_node = matcher.match("TECHNIQUE").where("_.name =~ '" + technique + "'").first()
            software_technique = Relationship(software_node, "RELATED", technique_node)
            tx.merge(software_technique)

    tx.commit()


def generate_attacker(cve_list):
    cve_list = list(dict.fromkeys(cve_list))
    print(len(cve_list))

    capec_list = []
    for cve_id in cve_list:
        capec_list += cve.capec(cve_id)
    capec_list = list(dict.fromkeys(capec_list))
    print(len(capec_list))
    
    preliminary_technique_list = []
    for capec_id in capec_list:
        preliminary_technique_list += capec.attack_technique(capec_id)
    preliminary_technique_list = list(dict.fromkeys(preliminary_technique_list))
    print(len(preliminary_technique_list))
    software_list = []
    for technique in preliminary_technique_list:
        software_list += attack.relationship_with(technique, "software")
    software_list = list(dict.fromkeys(software_list))
    print(len(software_list))
    profile = software_pool_profile(software_list)

    full_technique_list = []
    for software in software_list:
        full_technique_list += attack.relationship_with(software, "attack-pattern")
    full_technique_list = list(dict.fromkeys(full_technique_list))
    print(len(full_technique_list))
    cti_graph(cve_list, capec_list, preliminary_technique_list, software_list, full_technique_list)

    return profile, full_technique_list



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No CVE list to analyze. Please insert at least one CVE ID.\n")
        sys.exit(0)
    
    cve_list = sys.argv[1:]
    '''
    print('\n-------------------------------CVE-------------------------------')
    for cve_id in cve_list:
        print(cve_id)
    '''
    profile, technique_list = generate_attacker(cve_list)

    '''
    print('\n-------------------ATTACKER POSSIBILE TECHNIQUES-----------------')
    if len(technique_list) < 1:
        print("No techniques found in ATT&CK database.\n")
        sys.exit(0)

    else:
        print(len(technique_list))

        print('\n-----------------------ATTACKER PROFILE--------------------------')
        #print(json.dumps(profile, indent=4))

        print('\n------------------------ATTACKER IDENTIFICATION------------------')
        compatible_groups = fetch_groups(technique_list)
        if len(compatible_groups) > 1:
                print(len(compatible_groups))
        else:
            print("No groups found in ATT&CK Database for this technique pool.\n")
    '''
    print()
    sys.exit(0)

