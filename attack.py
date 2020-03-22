from mongocti import *
from paths import GROUP_URL

def fetch(attack_entity):
    attack_db = None
    if "attack-pattern" in attack_entity:
        attack_db = techniques_db
    elif "intrusion-set" in attack_entity:
        attack_db = groups_db
    elif "course-of-action" in attack_entity:
        attack_db = mitigations_db
    elif "tool" in attack_entity or "malware" in attack_entity:
        attack_db = software_db

    search_result = attack_db.find({'id':attack_entity})
    for entity in search_result:
        return entity

def relationship_with(attack_entity, entity_type=None):
    try:
        partners = []
        relationships = relationships_db.find({'$or': [{'target_ref': attack_entity}, {'source_ref': attack_entity}]})

        for entity in relationships:
            target = entity['target_ref']
            source = entity['source_ref']

            if entity_type == 'software':

                if attack_entity in target and ('tool' in source or 'malware' in source):
                    partners.append(source)

                elif attack_entity in source and ('tool' in target or 'malware' in target):
                    partners.append(target)
            
            else:
                if attack_entity in target and (entity_type in source):
                    partners.append(source)

                elif attack_entity in source and entity_type in target:
                    partners.append(target)

        return partners

    except:
        return []

def attack_id(attack_entity):
    attack_db = None
    if "attack-pattern" in attack_entity:
        attack_db = techniques_db
    elif "intrusion-set" in attack_entity:
        attack_db = groups_db
    elif "course-of-action" in attack_entity:
        attack_db = mitigations_db
    elif "tool" in attack_entity or "malware" in attack_entity:
        attack_db = software_db
    try:
        for external_reference in attack_db.distinct('external_references', {"external_references.source_name": {'$regex': '^.*-attack.*$'}, 'id':attack_entity}):
            if '-attack' in external_reference['source_name']:
                return external_reference['external_id']
        return attack_entity

    except:
        return attack_entity

def stix_id(attack_entity):
    category = attack_entity[0]
    if category == 'T':
        try:
            return techniques_db.distinct('id', {'external_references.external_id':attack_entity})[0]
        except:
            return attack_entity
    elif category == 'S':
        try:
            return software_db.distinct('id', {'external_references.external_id':attack_entity})[0]
        except:
            return attack_entity
    elif category == 'G':
        try:
            return groups_db.distinct('id', {'external_references.external_id':attack_entity})[0]
        except:
            return attack_entity    
    elif category == 'M':
        try:
            return mitigations_db.distinct('id', {'external_references.external_id':attack_entity})[0]
        except:
            return attack_entity
    else:
        return attack_entity

def capec(attack_technique):
    try:
        capec_list = []
        references = techniques_db.distinct("external_references", {"id":attack_technique})
        
        for reference in references:
            if reference['source_name'] == 'capec':
                capec_list.append(reference['external_id'].split("-")[1])
        
        return capec_list

    except:
        return []
    
def technique_platforms(attack_technique):
    try:
        return techniques_db.distinct('x_mitre_platforms', {'id':attack_technique})
    except:
        return []

def software_platforms(attack_software):
    try:
        return software_db.distinct('x_mitre_platforms', {'id':attack_software})
    except:
        return []

def permissions(attack_technique):
    try:
        return techniques_db.distinct('x_mitre_permissions_required', {'id':attack_technique})
    except:
        return []

def description(attack_technique):
    try:
        return techniques_db.distinct('description', {'id':attack_technique})
    except:
        return []

def name(attack_technique):
    try:
        return techniques_db.distinct('name', {'id':attack_technique})
    except:
        return []        

def data_sources(attack_technique):
    try:
        return techniques_db.distinct('x_mitre_data_sources', {'id':attack_technique})
    except:
        return []

def kill_chain_phases(attack_technique):
    try:
        return techniques_db.distinct('kill_chain_phases.phase_name', {'id':attack_technique})
    except:
        return []

def misp_threat_actor(attack_group):
    stix_id = attack_group.split("--")[1]
    attack_id = groups_db.distinct('external_references.external_id', {'external_references.source_name':'mitre-attack', 'id':attack_group})[0]
    threat_actors = []

    try:
        misp_list = threat_actors_db.distinct('uuid', {"meta.refs": GROUP_URL(attack_id)}) + threat_actors_db.distinct('uuid', {"related.dest-uuid": stix_id})
        for threat_actor in misp_list:
            if threat_actor not in threat_actors:
                threat_actors.append(threat_actor)
        
        return threat_actors
    except:
        return []

