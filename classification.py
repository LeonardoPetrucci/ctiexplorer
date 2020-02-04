from mongocti import *
import attack
import json
import misp_threat_actor
import capec

def list_count(array):
    count_list = {}
    for element in array:
        count_list[element] = array.count(element)
    return count_list

def software_properties(software):
    properties = {}

    nation = []
    goal = []
    target = []
    sponsor = []

    skills = []
    
    platforms = attack.software_platforms(software)

    techniques = attack.relationship_with(software, "attack-pattern")
    capec_list = []
    for technique in techniques:
        capec_list += attack.capec(technique)
    for capec_id in capec_list:
        skills += capec.skill(capec_id)

    groups = attack.relationship_with(software, "intrusion-set")
    threat_actors = []
    for group in groups:
        threat_actors += attack.misp_threat_actor(group)

    for threat_actor in threat_actors:
        nation += misp_threat_actor.country(threat_actor)
        goal += misp_threat_actor.type_of_incident(threat_actor)
        target += misp_threat_actor.target_category(threat_actor)
        sponsor += misp_threat_actor.suspected_state_sponsor(threat_actor)

    properties['nation'] = nation
    properties['goal'] = goal
    properties['target'] = target
    properties['sponsor'] = sponsor

    properties['skills'] = skills
    
    properties['platforms'] = platforms

    return properties

def software_pool_profile(software_pool):
    profile = {}
    
    for software in software_pool:
        properies = software_properties(software)
        for key in properies.keys():
            if key not in profile.keys():
                profile[key] = properies[key]
            else:
                profile[key] += properies[key]
    
    for key in profile.keys():
        profile[key] = list_count(profile[key])
    
    return profile


def fetch_groups(techniques):
    compatible_groups = []
    groups = groups_db.distinct("id", {})
    
    for group in groups:
        group_techniques = attack.relationship_with(group, "attack-pattern")
        if all(elem in techniques  for elem in group_techniques):
            compatible_groups.append(group)
    
    return compatible_groups