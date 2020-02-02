from mongocti import *

def country(actor):
    try:
        return threat_actors_db.distinct("meta.country", {'uuid':actor})

    except:
        return []

def type_of_incident(actor):
    try:
        return threat_actors_db.distinct("meta.cfr-type-of-incident", {'uuid':actor})

    except:
        return []

def target_category(actor):
    try:
        return threat_actors_db.distinct("meta.cfr-target-category", {'uuid':actor})

    except:
        return []

def suspected_state_sponsor(actor):
    try:
        return threat_actors_db.distinct("meta.cfr-suspected-state-sponsor", {'uuid':actor})

    except:
        return []

def suspected_victims(actor):
    try:
        return threat_actors_db.distinct("meta.cfr-suspected-victims", {'uuid':actor})

    except:
        return [] 

def attack_group(actor):
    pass

