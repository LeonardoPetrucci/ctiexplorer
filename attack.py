from mongocti import *
from paths import GROUP_URL

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

def capec(attack_technique):
    try:
        capec_list = []
        references = techniques_db.distinct("external_references.external_id", {"id":attack_technique})
        
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

