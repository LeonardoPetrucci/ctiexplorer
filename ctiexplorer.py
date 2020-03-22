import sys
import os
import cve
import capec
import attack
import json


from py2neo import Graph, Node, Relationship, NodeMatcher
from mongocti import *

default_uri = "bolt://localhost:7687"
default_user = "neo4j"
default_password = "cti"


def cti_graph(scenario, graph_uri=default_uri, graph_user=default_user, graph_password=default_password):
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
            for software in attack.relationship_with(technique, "software"):
                software_node = matcher.match("SOFTWARE").where("_.name =~ '" + attack.attack_id(software) + "'").first()
                technique_software = Relationship(capec_node, attack.attack_id(technique), software_node)
                tx.merge(technique_software)

    for software in software_list:
        software_node = matcher.match("SOFTWARE").where("_.name =~ '" + attack.attack_id(software) + "'").first()
        for group in attack.relationship_with(software, "intrusion-set"):
            group_node = matcher.match("GROUP").where("_.name =~ '" + attack.attack_id(group) + "'").first()
            software_group = Relationship(software_node, "RELATED", group_node)
            tx.merge(software_group)

    tx.commit()
    return


def generate_scenario(cve_list):
    scenario = {}

    cve_list = list(dict.fromkeys(cve_list))

    capec_list = []
    for cve_id in cve_list:
        capec_list += cve.capec(cve_id)
    capec_list = list(dict.fromkeys(capec_list))
    
    technique_list = []
    for capec_id in capec_list:
        technique_list += capec.attack_technique(capec_id)
    technique_list = list(dict.fromkeys(technique_list))

    software_list = []
    for technique in technique_list:
        software_list += attack.relationship_with(technique, "software")
    software_list = list(dict.fromkeys(software_list))

    group_list = []
    for software in software_list:
        group_list += attack.relationship_with(software, "intrusion-set")
    group_list = list(dict.fromkeys(group_list))

    scenario['cve'] = cve_list
    scenario['capec'] = capec_list
    scenario['technique'] = technique_list
    scenario['software'] = software_list
    scenario['group'] = group_list

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
        owasp['size'] = int(motive_sum / group_count)

    return owasp

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No CVE list to analyze. Please insert at least one CVE ID.\n")
        sys.exit(0)
    
    cve_list = sys.argv[1:]
    scenario = generate_scenario(cve_list)
    cti_graph(scenario)
    print(owasp_scenario(scenario))
    sys.exit(0)

