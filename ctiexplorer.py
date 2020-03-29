import sys
import os
import platform
import cve
import capec
import attack
import json
import paths
import shlex
import subprocess

from py2neo import Graph, Node, Relationship, NodeMatcher
from mongocti import *



default_uri = "bolt://localhost:7687"
default_user = "neo4j"
default_password = "cti"

def cti_mitigations_graph(scenario, graph_uri=default_uri, graph_user=default_user, graph_password=default_password):
    cve_list = scenario['cve']
    capec_list = scenario['capec']
    technique_list = scenario['technique']
    mitigation_list = scenario['mitigation']

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

    for technique in technique_list:
        technique_node = Node("TECHNIQUE", name=attack.attack_id(technique))
        tx.create(technique_node)

    for mitigation in mitigation_list:
        mitigation_node = Node("MITIGATION", name=attack.attack_id(mitigation))
        tx.create(mitigation_node)

    tx.commit()
    tx = g.begin()

    for cve_id in cve_list:
        cve_node = matcher.match("CVE").where("_.name =~ '" + cve_id + "'").first()
        for capec_id in cve.capec(cve_id):
            capec_node = matcher.match("CAPEC").where("_.name =~ '" + ('CAPEC-' + str(capec_id)) + "'").first()
            cve_capec = Relationship(cve_node, "ENABLES", capec_node)
            capec_cve = Relationship(capec_node, "EXPLOITS", cve_node)
            tx.merge(cve_capec, "RELATED", "name")
            tx.merge(capec_cve, "RELATED", "name")

    for capec_id in capec_list:
        capec_node = matcher.match("CAPEC").where("_.name =~ '" + ('CAPEC-' + str(capec_id)) + "'").first()
        for technique in capec.attack_technique(capec_id):
            technique_node = matcher.match("TECHNIQUE").where("_.name =~ '" + attack.attack_id(technique) + "'").first()
            capec_technique = Relationship(capec_node, "RELATED", technique_node)
            tx.merge(capec_technique, "RELATED", "name")
    
    for technique in technique_list:
        technique_node = matcher.match("TECHNIQUE").where("_.name =~ '" + attack.attack_id(technique) + "'").first()
        for mitigation in attack.relationship_with(technique, "course-of-action"):
            mitigation_node = matcher.match("MITIGATION").where("_.name =~ '" + attack.attack_id(mitigation) + "'").first()
            technique_mitigation = Relationship(technique_node, "RELATED", mitigation_node)
            tx.merge(technique_mitigation)
    
    tx.commit()
    return

def cti_groups_graph(scenario, graph_uri=default_uri, graph_user=default_user, graph_password=default_password):
    cve_list = scenario['cve']
    capec_list = scenario['capec']
    technique_list = scenario['technique']
    software_list = scenario['software']
    group_list = scenario['group']

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

    for technique in technique_list:
        technique_node = Node("TECHNIQUE", name=attack.attack_id(technique))
        tx.create(technique_node)

    for software in software_list:
        sofware_node = Node("SOFTWARE", name=attack.attack_id(software))
        tx.create(sofware_node)

    for group in group_list:
        group_node = Node("GROUP", name=attack.attack_id(group))
        tx.create(group_node)

    tx.commit()
    tx = g.begin()

    for cve_id in cve_list:
        cve_node = matcher.match("CVE").where("_.name =~ '" + cve_id + "'").first()
        for capec_id in cve.capec(cve_id):
            capec_node = matcher.match("CAPEC").where("_.name =~ '" + ('CAPEC-' + str(capec_id)) + "'").first()
            cve_capec = Relationship(cve_node, "ENABLES", capec_node)
            capec_cve = Relationship(capec_node, "EXPLOITS", cve_node)
            tx.merge(cve_capec, "RELATED", "name")
            tx.merge(capec_cve, "RELATED", "name")

    for capec_id in capec_list:
        capec_node = matcher.match("CAPEC").where("_.name =~ '" + ('CAPEC-' + str(capec_id)) + "'").first()
        for technique in capec.attack_technique(capec_id):
            if technique in technique_list:
                technique_node = matcher.match("TECHNIQUE").where("_.name =~ '" + attack.attack_id(technique) + "'").first()
                capec_technique = Relationship(capec_node, "RELATED", technique_node)
                tx.merge(capec_technique, "RELATED", "name")
    
    for technique in technique_list:
        technique_node = matcher.match("TECHNIQUE").where("_.name =~ '" + attack.attack_id(technique) + "'").first()
        for software in attack.relationship_with(technique, "software"):
            if software in software_list:
                software_node = matcher.match("SOFTWARE").where("_.name =~ '" + attack.attack_id(software) + "'").first()
                technique_software = Relationship(technique_node, "RELATED", software_node)
                tx.merge(technique_software)

    for software in software_list:
        software_node = matcher.match("SOFTWARE").where("_.name =~ '" + attack.attack_id(software) + "'").first()
        for group in attack.relationship_with(software, "intrusion-set"):
            group_node = matcher.match("GROUP").where("_.name =~ '" + attack.attack_id(group) + "'").first()
            software_group = Relationship(software_node, "RELATED", group_node)
            tx.merge(software_group)

    tx.commit()
    return


def generate_scenario(cve_list, os_version):
    scenario = {}

    cve_list = list(dict.fromkeys(cve_list))

    capec_list = []
    for cve_id in cve_list:
        capec_list += cve.capec(cve_id)
    capec_list = list(dict.fromkeys(capec_list))
    
    technique_list = []
    for capec_id in capec_list:
        technique_list += capec.attack_technique(capec_id)
    for technique in technique_list:
        if os_version not in attack.technique_platforms(technique):
            technique_list.remove(technique)
    technique_list = list(dict.fromkeys(technique_list))

    software_list = []
    for technique in technique_list:
        software_list += attack.relationship_with(technique, "software")
    for software in software_list:
        if os_version not in attack.software_platforms(software):
            software_list.remove(software)
    software_list = list(dict.fromkeys(software_list))

    group_list = []
    for software in software_list:
        group_list += attack.relationship_with(software, "intrusion-set")
    group_list = list(dict.fromkeys(group_list))

    mitigation_list = []
    for technique in technique_list:
        mitigation_list += attack.relationship_with(technique, 'course-of-action')
    mitigation_list = list(dict.fromkeys(mitigation_list))

    scenario['cve'] = cve_list
    scenario['capec'] = capec_list
    scenario['technique'] = technique_list
    scenario['software'] = software_list
    scenario['group'] = group_list
    scenario['mitigation'] = mitigation_list

    return scenario

def owasp_scenario(scenario):
    owasp = {}

    owasp['skill_level'] = 'Unknown'
    owasp['motive'] = 'Unknown'
    owasp['opportunity'] = 'Unknown'
    owasp['size'] = 'Unknown'


    skill_level_sum = 0
    skill_level_entities = 0

    for technique in scenario['technique']:
        level = attack.fetch(technique)['level']
        if level != 'Unknown':
            skill_level_entities += 1
            skill_level_sum += int(level)
    
    if skill_level_entities != 0:
        owasp['skill_level'] = int(skill_level_sum / skill_level_entities)
    

    opportunity_sum = 0
    opportunity_entities = 0

    for software in scenario['software']:
        score = attack.fetch(software)['score']
        if score != 'Unknown':

            opportunity_entities += 1
            opportunity_sum += int(score)

    if opportunity_entities != 0:
        owasp['opportunity'] = int(opportunity_sum / opportunity_entities)
    
    group_count = 0
    motive_sum = 0
    size_sum = 0

    for group in scenario['group']:
        motive = attack.fetch(group)['motive']
        size = attack.fetch(group)['size']
        if motive != 'Unknown' and size != 'Unknown':

            software_group = attack.relationship_with(group, 'software')
            used_sw = 0
            total_sw = len(software_group)
            for software in software_group:
                if software in scenario['software']:
                    used_sw += 1

            weight = float(used_sw / total_sw)
            group_count += weight
            motive_sum += float(motive) * weight
            size_sum += float(size) * weight
    
    if group_count != 0:
        owasp['motive'] = int(motive_sum / group_count)
        owasp['size'] = int(size_sum / group_count)
    
    if 'Unknown' in owasp.values():
        print('Missing some information related to the selected CVE.\n')
        return {}

    return owasp


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No CVE list to analyze. Please insert at least one CVE ID.\n")
        sys.exit(0)

    mode = sys.argv[1]
    option = None
    if len(mode) == 3:
        option = mode[-1]
        mode = mode[:-1]

    elif len(mode) < 2 or len(mode) > 3:
        print('Invalid mode.')
        sys.exit(1)
    
    if option == 'R':
        agreement = input('CAUTION! YOU ARE IN RUNNING MODE.\nPlease keep in mind the actions LOCALLY performed by eventual collected TTPs can be dangerous.\nUse this mode only if you know what are you doing.\nAre you sure to use run mode? [y/N] ')
        if agreement.lower() != 'y':
            sys.exit(0)
        if 'atomic-red-team' not in os.listdir(paths.current_directory):
            print('Atomic Red Team library not found. Will be cloned now.\n')
            git_clone_art = subprocess.run(shlex.split('git clone https://github.com/redcanaryco/atomic-red-team.git'), stdout=subprocess.PIPE, universal_newlines=True)
            git_clone_art
        else:
            print('Atomic Red Team library found.\n')
        
        from atomic_runner import run_techniques

    if mode == '-U':
        pass

    elif mode == '-W':
        pass
    
    elif mode == '-T':
        if '.json' not in sys.argv[2]:
            print('ERROR: Expected a JSON file for run in topology mode.\n')
        #TODO: Manage topology json file
        sys.exit(1)

    elif mode == '-L':
        os_version = platform.system()
        if os_version == 'Darwin':
            os_version = 'macOS'

        print('Running on a ' + os_version + ' host.\n')

        cve_list = sys.argv[2:]
        
        if len(cve_list) == 0:
            print("No CVE list to analyze. Please insert at least one CVE ID.\n")
            sys.exit(0)

        scenario = generate_scenario(cve_list, os_version)
        
        owasp_threat_agent = owasp_scenario(scenario)
        if 'Unknown' in owasp_threat_agent.values():
            print('Cannot define Threat Actor factors for this scenario.\n')
        else:
            skill_level = str(owasp_threat_agent['skill_level'])
            motive = str(owasp_threat_agent['motive'])
            opportunity = str(owasp_threat_agent['opportunity'])
            size = str(owasp_threat_agent['size'])

            print('Possible Threat Agent defined.')
            print('Skill Level: ' + skill_level)
            print('Motive: ' + motive)
            print('Opportunity: ' + opportunity)
            print('Size: ' + size)
            print('\nPlease continue your Risk Rating process by clicking the link below.')
            print('https://owasp-risk-rating.com/?vector=(SL:' + skill_level + '/M:' + motive + '/O:' + opportunity + '/S:' + size + ')\n')

        if option == 'M':
            cti_mitigations_graph(scenario)
        else:
            cti_groups_graph(scenario) 
        
            
            if option == 'R':
                techniques = scenario['technique']
                if len(techniques) > 0:
                    run_techniques(techniques)
                else:
                    print("No technique found for execution.")

    else:
        print("Invalid option.\n")

    sys.exit(0)