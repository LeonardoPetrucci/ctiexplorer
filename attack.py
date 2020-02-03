from mongocti import *
from paths import GROUP_URL

def capec(attack_technique):
    try:
        capec_list = []
        references = techniques_db.distict("external_references.external_id", {"id":attack_technique})
        
        for reference in references:
            if reference['source_name'] == 'capec':
                capec_list.append(reference['external_id'].split("-")[1])
        
        return capec_list

    except:
        return []
    

def attack_relationship_with(attack_entity, entity_type=None):
    try:
        partners = []
        relationships = relationships_db.find({'$or': [{'target_ref': attack_entity}, {'source_ref': attack_entity}]})

        for entity in relationships:
            target = entity['target_ref']
            source = entity['source_ref']

            if attack_entity in target and entity_type in source:
                partners.append(source)

            elif attack_entity in source and entity_type in target:
                partners.append(target)

        return partners

    except:
        return []

def platforms(attack_technique):
    try:
        return techniques_db.distict('x_mitre_platforms', {'id':attack_technique})
    except:
        return []

def permissions(attack_technique):
    try:
        return techniques_db.distict('x_mitre_permissions_required', {'id':attack_technique})
    except:
        return []

def data_sources(attack_technique):
    try:
        return techniques_db.distict('x_mitre_data_sources', {'id':attack_technique})
    except:
        return []

def kill_chain_phases(attack_technique):
    try:
        return techniques_db.distict('kill_chain_phases.phase_name', {'id':attack_technique})
    except:
        return []

def misp_threat_actor(attack_group):
    stix_id = attack_group.split("--")[1]
    attack_id = groups_db.distinct('external_references.external_id', {'external_references.source_name':'mitre-attack', 'id':attack_group})[0]
    threat_actors = []

    try:
        misp_list = threat_actors_db.distinct('uuid', {"meta.refs": GROUP_URL(attack_id)}) + threat_actors_db.distinct('uuid', {"related.dest-uuid": stix_id})
        for element in misp_list:
            if element not in threat_actors:
                threat_actors.append(element)
        
        return threat_actors
    except:
        return []

print(misp_threat_actor("intrusion-set--6a2e693f-24e5-451a-9f88-b36a108e5662"))