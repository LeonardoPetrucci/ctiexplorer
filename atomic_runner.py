import os
import sys

sys.path.append(os.path.abspath('atomic-red-team/execution-frameworks/contrib/python'))
import runner

import attack

def run_techniques(technique_list):
    execute_flag = input(str(len(technique_list)) + " techniques found in MITRE ATT&CK. Would you like to start their execution? y/N ")
    if execute_flag == 'y':
        techniques = runner.AtomicRunner()
        while(True):
            mode = input("Select the execution mode number, or type h for a list of execution options: ")
            help = "Mode of operations:\n1- manual: execute all tecnhiques found in manual mode. Command and options will be shown\n2- all-automatic: execute automatically all the techniques found with default paramenters.\n3- single-manual: execute a single technique in manual mode\n4- automatic-manual: execute a single technique in automatic mode\n"
            print(help)
            if mode == 'h':
                print("Mode of operations:\n1- all-manual: execute all tecnhiques found in manual mode. Command and options will be shown\n2- all-automatic: execute automatically all the techniques found with default paramenters.\n3- single-manual: execute a single technique in manual mode\n4- automatic-manual: execute a single technique in automatic mode\n")
            elif mode == '1' or mode == '2':
                for technique in technique_list:
                    if mode == '1':
                        try:
                            techniques.interactive_execute(attack.attack_id(technique))
                        except:
                            print("Technique " + technique + " not supported by Atomic Red Team.\n")
                    elif mode == '2':
                        try:
                            techniques.execute(attack.attack_id(technique))
                        except:
                            print("Technique " + technique + " not supported by Atomic Red Team.\n")
            elif mode == '3' or mode == '4':
                while(True):
                    select_message = "Insert technique number (type list for the full technique list) or type exit for finishing the executions: "
                    select = input(select_message)
                    if select == 'exit':
                        return
                    elif select == 'list':
                        for technique in technique_list:
                            print(str(attack.attack_id(technique)) + " - " + str(attack.name(technique)))
                    else:
                        if attack.stix_id(select) in technique_list:
                            technique = select
                            if mode == '3':
                                try:
                                    techniques.interactive_execute(attack.attack_id(technique))
                                except:
                                    print("Technique " + technique + " not supported by Atomic Red Team.\n")
                            elif mode == '4':
                                try:
                                    techniques.interactive_execute(attack.attack_id(technique))
                                except:
                                    print("Technique " + technique + " not supported by Atomic Red Team.\n")
                        else:
                            print("Technique not found in ATT&CK Technique list for this scenario.\n")
            else:
                print("Invalid option.\n")
    return