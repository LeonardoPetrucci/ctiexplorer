def list_count(array):
    count_list = {}
    for element in array:
        count_list[element] = array.count(element)
    return count_list

#STUB: This classification metrics MUST be improved
def threat_actor_category(threat_actor):
    if 'meta' in threat_actor.keys():
        if 'cfr-suspected-state-sponsor' in threat_actor['meta'].keys():
            threat_actor['category'] = 'State-Sponsored'
            threat_actor['motive'] = '9'
            threat_actor['size'] = '2'
        else:
            threat_actor['category'] = 'Cyber Criminal'
            threat_actor['motive'] = '4'
            threat_actor['size'] = '6'

    if 'category' not in threat_actor.keys():
        threat_actor['category'] = 'Unknown'
    
    return threat_actor


