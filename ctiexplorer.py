import sys
import os
import cve
import capec
import attack
import json

sys.path.append(os.path.abspath(os.path.join('..', 'atomic-red-team/execution-frameworks/contrib/python')))
import runner

from py2neo import Graph, Node, Relationship, NodeMatcher
from mongocti import *
from classification import software_pool_profile, fetch_groups

default_uri = "bolt://localhost:7687"
default_user = "neo4j"
default_password = "cti"


def cti_graph(scenario, graph_uri=default_uri, graph_user=default_user, graph_password=default_password):
    cve_list = scenario['cve']
    capec_list = scenario['capec']
    preliminary_technique_list = scenario['preliminary_technique']
    software_list = scenario['software']
    full_technique_list = scenario['technique']

    g = Graph(uri=graph_uri, user=graph_user, password=graph_password)
    matcher = NodeMatcher(g)
    g.delete_all()
    tx = g.begin()

    for cve_id in cve_list:
        cve_node = Node("CVE", name=cve_id)
        tx.create(cve_node)
    
    for capec_id in capec_list:
        capec_node = Node("CAPEC", name=('CAPEC-' + str(capec_id)))
        tx.create(capec_node)

    for preliminary_technique in preliminary_technique_list:
        preliminary_technique_node = Node("PRELIMINARY_TECHNIQUE", name=attack.attack_id(preliminary_technique))
        tx.create(preliminary_technique_node)
    
    for software in software_list:
        sofware_node = Node("SOFTWARE", name=attack.attack_id(software))
        tx.create(sofware_node)

    for technique in full_technique_list:
        technique_node = Node("TECHNIQUE", name=attack.attack_id(technique))
        tx.create(technique_node)

    tx.commit()
    tx = g.begin()

    for cve_id in cve_list:
        cve_node = matcher.match("CVE").where("_.name =~ '" + cve_id + "'").first()
        for capec_id in cve.capec(cve_id):
            capec_node = matcher.match("CAPEC").where("_.name =~ '" + ('CAPEC-' + str(capec_id)) + "'").first()
            cve_capec = Relationship(cve_node, "RELATED", capec_node)
            tx.merge(cve_capec, "RELATED", "name")

    for capec_id in capec_list:
        capec_node = matcher.match("CAPEC").where("_.name =~ '" + ('CAPEC-' + str(capec_id)) + "'").first()
        for preliminary_technique in capec.attack_technique(capec_id):
            preliminary_technique_node = matcher.match("PRELIMINARY_TECHNIQUE").where("_.name =~ '" + attack.attack_id(preliminary_technique) + "'").first()
            capec_preliminary_technique = Relationship(capec_node, "RELATED", preliminary_technique_node)
            tx.merge(capec_preliminary_technique, "RELATED", "name")
    
    for preliminary_technique in preliminary_technique_list:
        preliminary_technique_node = matcher.match("PRELIMINARY_TECHNIQUE").where("_.name =~ '" + attack.attack_id(preliminary_technique) + "'").first()
        for software in attack.relationship_with(preliminary_technique, "software"):
            software_node = matcher.match("SOFTWARE").where("_.name =~ '" + attack.attack_id(software) + "'").first()
            preliminary_technique_software = Relationship(preliminary_technique_node, "RELATED", software_node)
            tx.merge(preliminary_technique_software)

    for software in software_list:
        software_node = matcher.match("SOFTWARE").where("_.name =~ '" + attack.attack_id(software) + "'").first()
        for technique in attack.relationship_with(software, "attack-pattern"):
            technique_node = matcher.match("TECHNIQUE").where("_.name =~ '" + attack.attack_id(technique) + "'").first()
            software_technique = Relationship(software_node, "RELATED", technique_node)
            tx.merge(software_technique)

    tx.commit()
    return


def run_techniques(technique_list):
    execute_flag = input(str(len(technique_list)) + " techniques found in MITRE ATT&CK. Would you like to start their execution? y/N ")
    if execute_flag == 'y':
        techniques = runner.AtomicRunner()
        while(True):
            mode = input("Select the execution mode number, or type h for a list of execution options: ")
            help = "Mode of operations:\n1- manual: execute all tecnhiques found in manual mode. Command and options will be shown\n2- all-automatic: execute automatically all the techniques found with default paramenters.\n3- single-manual: execute a single technique in manual mode\n4- automatic-manual: execute a single technique in automatic mode\n"
            print(help)
            if mode == 'h':
                print("Mode of operations:\n1- all-manual: execute all tecnhiques found in manual mode. Command and options will be shown\n2- all-automatic: execute automatically all the techniques found with default paramenters.\n3- single-manual: execute a single technique in manual mode\n4- automatic-manual: execute a single technique in automatic mode\n")
            elif mode == '1' or mode == '2':
                for technique in technique_list:
                    if mode == '1':
                        try:
                            techniques.interactive_execute(attack.attack_id(technique))
                        except:
                            print("Technique " + technique + " not supported by Atomic Red Team.\n")
                    elif mode == '2':
                        try:
                            techniques.execute(attack.attack_id(technique))
                        except:
                            print("Technique " + technique + " not supported by Atomic Red Team.\n")
            elif mode == '3' or mode == '4':
                while(True):
                    select_message = "Insert technique number (type list for the full technique list) or type exit for finishing the executions: "
                    select = input(select_message)
                    if select == 'exit':
                        return
                    elif select == 'list':
                        for technique in techniques:
                            print(attack.attack_id(technique) + " - " + attack.description(technique))
                    else:
                        if select in technique_list:
                            technique = select
                            if mode == '1':
                                try:
                                    techniques.interactive_execute(attack.attack_id(technique))
                                except:
                                    print("Technique " + technique + " not supported by Atomic Red Team.\n")
                            elif mode == '2':
                                try:
                                    techniques.interactive_execute(attack.attack_id(technique))
                                except:
                                    print("Technique " + technique + " not supported by Atomic Red Team.\n")
                        else:
                            print("Technique not found in ATT&CK Technique list for this scenario.\n")
            else:
                print("Invalid option.\n")
    return

def generate_scenario(cve_list):
    scenario = {}

    cve_list = list(dict.fromkeys(cve_list))

    capec_list = []
    for cve_id in cve_list:
        capec_list += cve.capec(cve_id)
    capec_list = list(dict.fromkeys(capec_list))
    
    preliminary_technique_list = []
    for capec_id in capec_list:
        preliminary_technique_list += capec.attack_technique(capec_id)
    preliminary_technique_list = list(dict.fromkeys(preliminary_technique_list))

    software_list = []
    for technique in preliminary_technique_list:
        software_list += attack.relationship_with(technique, "software")
    software_list = list(dict.fromkeys(software_list))

    

    full_technique_list = []
    for software in software_list:
        full_technique_list += attack.relationship_with(software, "attack-pattern")
    full_technique_list = list(dict.fromkeys(full_technique_list))

    scenario['cve'] = cve_list
    scenario['capec'] = capec_list
    scenario['preliminary_technique'] = preliminary_technique_list
    scenario['software'] = software_list
    scenario['technique'] = full_technique_list

    return scenario


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No CVE list to analyze. Please insert at least one CVE ID.\n")
        sys.exit(0)
    
    cve_list = sys.argv[1:]
    
    scenario = generate_scenario(cve_list)
    profile = software_pool_profile(scenario['software'])
    technique_list = scenario['technique']
    
    cti_graph(scenario)

    if len(technique_list) < 1:
        print("No techniques found in ATT&CK database.\n")
        sys.exit(0)

    else:
        print(json.dumps(profile, indent=4))
        run_techniques(technique_list)
    
    print()    
    sys.exit(0)

