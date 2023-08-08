#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on Jul 13, 2017
Last updated on Aug 3, 2017

@author: tskanai
'''

import sys
import getpass
import json
try:
    from elam_report_generator import get_elam_report
except:
    from elam_tool2.elam_report_generator import get_elam_report
import multiprocessing
import time
#from buildtools import process

def get_elam_multidev(run_dev = {}, user_pass = {}, elam_trigger_list = []):
    elam_trigger_sort = {'ingress': [], 'egress': []}
    for elam_trigger in elam_trigger_list:
        if elam_trigger['direction'] == 'ingress':
            elam_trigger_sort['ingress'].append(elam_trigger)
        elif elam_trigger['direction'] == 'egress':
            elam_trigger_sort['egress'].append(elam_trigger)
        else:
            print('Error: direction must be either \'ingress\' or \'egress\'.')
    num_ingress = len(elam_trigger_sort['ingress'])
    num_egress = len(elam_trigger_sort['egress'])
    if ( (num_ingress > 2 or num_egress > 2) ) or (num_ingress + num_egress < 1):
        print('Error: max number of ingress/egress leaves is 2 respectively, and at least one leaf (either ingress or egress) must be selected.')
    else:
        None
    
    Processes = {'ingress': [], 'egress': []}
    #queue = Queue()
    #sem = Semaphore(4)

    for direction in ['ingress', 'egress']:
        for elam_trigger in elam_trigger_sort[direction]:
            Process = multiprocessing.Process(target=get_elam_report, name = elam_trigger['node-name'], args=(run_dev, user_pass, elam_trigger))
            Processes[direction].append(Process)
            Process.start()
            #Process.join()

    waiting_time = 0
    process_active = True
    while process_active and waiting_time < 600:
        total_active_count = 0
        for direction in ['ingress', 'egress']:
            finished_process = 0
            for Process in Processes[direction]:
                if Process.is_alive():
                    print('[' + Process.name + '] process is still alive.')
                    total_active_count += 1
                else:
                    print('[' + Process.name + '] process is done!')
                    finished_process += 1
            if finished_process > 0:
                for Process in Processes[direction]:
                    if Process.is_alive():
                        print('[' + Process.name + '] process is manually terminated.')
                        Process.terminate()
                    else:
                        continue
            else:
                continue
        if total_active_count == 0:
            process_active = False
        else:
            print('(multiprocessing) There is at least one active process. Continue...')         
        waiting_time += 5
        time.sleep(5)
        
    return True   

def main():
    try:
        sys.argv[1]
    except Exception:        
        print('Error: Please specify a json file as an argument.')
        exit()
    else:
        None

    run_at = input('On which platform are you running the script, client or apic? [client/apic]: ')
    while run_at != 'client' and run_at != 'apic':
        run_at = input('answer [client/apic]: ')
    else:
        None
    
    if run_at == 'client':
        apic_ip = input('APIC IP: ')
        run_dev = {"run_at": run_at, "apic_ip": apic_ip}
    elif run_at == 'apic':
        run_dev = {"run_at": run_at}
    else:
        print('Error: Platform must be either client or apic.')
        
    username = input('username: ')
    password = getpass.getpass('password: ')
    user_pass = {'username': username, 'password': password}

        
    try:
        with open(sys.argv[1], 'r') as trigger_json:
        #with open('trigger.json', 'r') as trigger_json:
            elam_trigger_list = json.loads(trigger_json.read())
    except Exception:
        print('Error: Cannot open the specified file.')
        exit()
    
    get_elam_multidev(run_dev, user_pass, elam_trigger_list)


if __name__ == '__main__':
    main()
    
