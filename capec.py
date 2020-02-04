from mongocti import *

def cwe(capec):
    try:
        return capec_db.distinct("Related_Weaknesses.Related_Weakness.CWE_ID", {"ID":capec})

    except:
        return []

def attack_technique(capec):
    try:
        attack_technique_list = []
        taxonomies = capec_db.distinct("Taxonomy_Mappings.Taxonomy_Mapping", {"ID": capec})
        for taxonomy in taxonomies:
            if "ATTACK" in taxonomy["Taxonomy_Name"]:
                attack_id = "T" + taxonomy["Entry_ID"]
                attack_technique_list += techniques_db.distinct("id", {"external_references.external_id": attack_id})

        return attack_technique_list

    except:
        return []

def likelihood(capec):
    try:
        return capec_db.distinct("Likelihood_Of_Attack", {"ID":capec})

    except:
        return []

def severity(capec):
    try:
        return capec_db.distinct("Typical_Severity", {"ID":capec})

    except:
        return []

def prerequisites(capec):
    try:
        return capec_db.distinct("Prerequisites.Prerequisite", {"ID":capec})

    except:
        return []

def skill(capec):
    try:
        return capec_db.distinct("Skills_Required.Skill.Level", {"ID":capec})

    except:
        return []


def consequences(capec):
    try:
        return capec_db.distinct("Consequences.Consequence.Scope", {"ID":capec})

    except:
        return []

def resources(capec):
    try:
        return capec_db.distinct("Resources_Required.Resource", {"ID":capec})

    except:
        return []

