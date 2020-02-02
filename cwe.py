from mongocti import *

def capec(cwe):
    try:
        return cwe_db.distinct("Related_Weaknesses.Related_Weakness.CWE_ID", {"ID":cwe})
    except:
        return []

def impact(cwe):
        try:
        return cwe_db.distinct("Common_Consequences.Consequence.Impact", {"ID":cwe})
    except:
        return []

def likelihood(cwe):
    try:
        return cwe_db.distinct("Likelihood_Of_Exploit", {"ID":cwe})
    except:
        return []

def consequences(cwe):
    try:
        return cwe_db.distinct("Common_Consequences.Consequence.Scope", {"ID":cwe})
    except:
        return []

