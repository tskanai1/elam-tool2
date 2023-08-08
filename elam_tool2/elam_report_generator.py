#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Created on Jun 27, 2017
Last updated on May 10, 2022

@author: tskanai, tokyu, keiish, koiwata, takasano, yyanomor
'''
from operator import is_
import pexpect
import getpass
import re
import time
import sys
import json
import getopt
import multiprocessing
import os
from multiprocessing import Value

ereport_supported_version = 14.2

supported_in_out_select = {
    "gen2+": {
        #"10": ['0', '1', '2'],
        #"13": ['0', '1', '2'],
        #"15": ['0', '1', '2'],
        "6": {"out-select": ['0', '1', '2'], "inner_outer": 'outer'},
        "7": {"out-select": ['0', '1', '2'], "inner_outer": 'inner'},
        "14": {"out-select": ['0', '1', '2'], "inner_outer": 'inner'}
        #"8": ['0', '1', '2'],
        #"9": ['0', '1', '2']
    },
    "gen1": {
        "3": {"out-select": ['0', '03', '1', '2', '4', '5'], "inner_outer": 'outer'},
        "4": {"out-select": ['0', '04', '1', '2', '3', '5'], "inner_outer": 'inner'}
        #"5": ['0', '05', '1', '2', '3', '4'],
        #"6": ['0', '1', '2', '3', '4', '5'],
        #"7": ['0', '1', '2', '3', '4', '5']
    }
}

def get_elam_report(run_dev = {}, user_pass = {}, elam_trigger = {}, elam_timeout = 600):

    node_name = elam_trigger["node-name"]
    username = user_pass["username"]
    password = user_pass["password"]

    ### Starting login each device. 
    if run_dev["run_at"] == 'client':
        child = pexpect.spawn('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=no %s@%s' % (username, run_dev["apic_ip"]), timeout = 60)
        print('apic login')
        child.expect('password:')
        child.sendline(password)
        child.expect('#')
    elif run_dev["run_at"] == 'apic':
        child = pexpect.spawn('zsh', timeout = 60)
        child.expect('#')
    else:
        print('Error: \'run_at\' must be either \'client\' or \'apic\'.')
        return False
    
    child.sendline('show controller | grep "*" | head -1 | awk \'{print $3}\'')
    child.expect('#')
    infra_apic_ip = re.split(r'[\n\r]+', child.before.decode('utf-8'))[1]
    #print (infra_apic_ip)
    child.sendline('ssh -b %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s@%s' % (infra_apic_ip, username, node_name))
    print('switch ' + node_name + ' login')
    child.expect('Password:')
    child.sendline(password)
    child.expect('#')

    # GET LC number
    child.sendline('moquery -c eqptLC | grep id | awk \'{print $3}\'')
    child.expect('#')    
    lc = child.before.decode('utf-8').split('\r\n')[1:-1]

    # Check box-type or modular-type switch
    child.sendline('show module | grep "Fabric Module" | wc -l')
    child.expect('#')
    box = int(re.split(r'[\n\r]+', child.before.decode('utf-8'))[1])

    trigger_count = Value('i', 0)

    if box == 0:
        print('Identified as box-type switch')
        elam_generate(run_dev, "1", "0", elam_trigger, user_pass, elam_timeout, box, trigger_count)
    else:
        print('Identified as modular-type switch')
        Processes = []
        for lc_number in lc:
            # GET ASIC number
            child.sendline('moquery -c eqptAsic | grep dn | awk \'{print $3}\' | grep lcslot-' + lc_number + ' | rev | cut -c 1 | rev ')
            child.expect('#')
            asic_numbers = child.before.decode('utf-8').split('\r\n')[1:-1]
        
            # ELAM Generate with lc_number and asic_number
            for asic_number in asic_numbers:
                int_asic_number = int(asic_number) - 1
                asic_number = str(int_asic_number)
                print("Process Start (ASIC:" + asic_number + " on LC:" + lc_number + ") !!!!!!!!!")

                Process = multiprocessing.Process(target=elam_generate, args=(run_dev, lc_number, asic_number, elam_trigger, user_pass, elam_timeout, box, trigger_count))
                Processes.append(Process)
                Process.start()
                time.sleep(0.5)
            
        waiting_time = 0
        process_active = True

        while process_active and waiting_time < elam_timeout:
            total_active_count = 0
            finished_process = 0
            for Process in Processes:
                if Process.is_alive():
                    #print('[' + Process.name + '] process is still alive.')
                    total_active_count += 1
                else:
                    #print('[' + Process.name + '] process is done!')
                    finished_process += 1
                    #print("Finish -> " + str(finished_process))
            if finished_process > 0 and finished_process >= trigger_count.value:
                for Process in Processes:
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
    print ("The script completed !!!!!!!!")
    child.close()
    return True


def check_asic_family(asic, elam_trigger):
    ### Check if each parameter is acceptable.
    if asic != 'tah' and asic != 'roc' and asic != 'app' and asic != 'cho' and asic != 'ns' and asic != 'alp':
        print('Error: Supported asic is \'tah\' or \'roc\' or \'app\' or \'cho\' or \'ns\' or \'alp\'.')
        return False
    elif asic == 'ns' or asic == 'alp':
        if elam_trigger["role"] == "leaf":
            if elam_trigger["direction"] == 'ingress':
                elam_trigger["in-select"] = "3"
                elam_trigger["out-select"] = "0"
            elif elam_trigger["direction"] == 'egress':
                elam_trigger["in-select"] = "4"
                elam_trigger["out-select"] = "0"
            else:
                print('Error: Gen1 Leaf\'s direction must be \'ingress\' or \'egress\'.')
                return False
        else:
            if elam_trigger["direction"] == 'ingress':
                elam_trigger["in-select"] = "4"
                elam_trigger["out-select"] = "0"
            else:
                print('Error: Gen1 Spine\'s direction must be \'ingress\'.')
                return False
        
    else:
        None
    return True

def check_each_parameter(asic, elam_trigger):

    in_select = elam_trigger["in-select"]
    out_select = elam_trigger["out-select"]

    if in_select in supported_in_out_select[asic]:
        None
    else:
        print('Error: for', asic, 'asic currently supported by this tool is only')
        for key in supported_in_out_select[asic]:
            print(key, end=' ')
        print('.')
        return False
        
    if out_select in supported_in_out_select[asic][in_select]["out-select"]:
        None
    else:
        print('Error: Supported out-select for', asic, 'asic is', end=' ')
        for elem in supported_in_out_select[asic][in_select]:
            print(elem, end=' ')
        print('.')
        return False
    
    return True

def check_nodename_or_nodeid_validity(input_str, mo_topSystem):
    output_bool = False
    for i in range(len(mo_topSystem['imdata'])):
        if input_str == str(mo_topSystem['imdata'][i]['topSystem']['attributes']['id']):
            output_bool = True
            break
        if input_str == mo_topSystem['imdata'][i]['topSystem']['attributes']['name']:
            output_bool = True
            break
    return output_bool

def elam_generate(run_dev, lc_number, asic_number, elam_trigger, user_pass, elam_timeout, box, trigger_count):

    elam_report = []
    node_name = elam_trigger["node-name"]
    inner_outer = ''
    
    username = user_pass["username"]
    password = user_pass["password"]

    elam_start_point = { 
        "ereport" : " ELAM REPORT",
        "report detail" : "######",
        "report" : "######",
        }

    if run_dev["run_at"] == 'client':
        child = pexpect.spawn('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=no %s@%s' % (username, run_dev["apic_ip"]), timeout = 60)
        child.expect('password:')
        child.sendline(password)
        child.expect('#')
    elif run_dev["run_at"] == 'apic':
        child = pexpect.spawn('zsh', timeout = 60)
        child.expect('#')
    else:
        return False
    
    child.sendline('show controller | grep "*" | head -1 | awk \'{print $3}\'')
    child.expect('#')
    infra_apic_ip = re.split(r'[\n\r]+', child.before.decode('utf-8'))[1]
    #print (infra_apic_ip)
    child.sendline('ssh -b %s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no %s@%s' % (infra_apic_ip, username, node_name))
    child.expect('Password:')
    child.sendline(password)
    child.expect('#')

    # GET Version
    child.sendline('moquery -c topSystem | grep version')
    child.expect('#')
    result = re.search('(\d+\.\d+)', child.before.decode('utf-8'))
    version = result.group(1)

    if box == 0:
        child.sendline('vsh_lc')
        child.expect('#')
    
    else:
        child.sendline('vsh')
        child.expect('#')
        child.sendline('attach module ' + lc_number)
        child.expect('#')
    
    # Check asic family and each parameter
    child.sendline('show platform internal hal objects platform asic | no-more')
    child.expect('module-' + lc_number + '#')
    sh_plat_int_hal_obj_plat_asic = child.before.decode('utf-8')
    # In the case of gen1
    if 'Internal error during command execution' in sh_plat_int_hal_obj_plat_asic:
        if elam_trigger['role'] == 'leaf':
            asic = 'ns'
        else:
            asic = 'alp'
        if check_asic_family(asic, elam_trigger) == False:
            return False
        asic_gen = 'gen1'
    # In the case of gen2 or later
    else:
        m = re.search(r"family\s+: (\S+)", sh_plat_int_hal_obj_plat_asic)
        asic = m.group(1)[:3]
        if check_asic_family(asic, elam_trigger) == False:
            return False
        asic_gen = 'gen2+'
    # Check other parameters
    if check_each_parameter(asic_gen, elam_trigger) == False:
        return False
    in_select = elam_trigger["in-select"]
    out_select = elam_trigger["out-select"]
    inner_outer = supported_in_out_select[asic_gen][in_select]["inner_outer"]
    
    child.sendline('debug platform internal ' + asic + ' elam asic ' + asic_number)
    child.expect('#')
    print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] debug platform internal ' + asic + ' elam asic' + asic_number)
    
    if asic == 'ns' or asic == 'alp':
        init_trigger = 'trigger init ' + elam_trigger["direction"] + ' in-select ' + in_select + ' out-select ' + out_select
    else:
        init_trigger = 'trigger init in-select ' + in_select + ' out-select ' + out_select
    child.sendline(init_trigger)
    print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ' + init_trigger)
    child.expect('#')
    child.sendline('reset')
    child.expect('#')
    child.sendline('status')
    child.expect('#')
    status = re.split('[\n\r]+', child.before.decode('utf-8'))[1:-1]
    for line in status:
        if re.search('.*Armed.*', line) or re.search('.*Triggered.*', line):
            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Error: elam trigger cannot be reset.')
            return False
        else:
            continue
    print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ELAM trigger is successfully reset.')
    if elam_trigger["trigger"]["arp"] == 'yes':
        trigger_arp = elam_trigger["trigger"]["children"][0]["arp"]
        set_arp = 'set ' + inner_outer + ' arp'
        if trigger_arp["source-ip-addr"] == '' and trigger_arp["source-mac-addr"] == '' and trigger_arp["target-ip-addr"] == '' and trigger_arp["traget-mac-addr"] == '':
            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Error: trigger for ARP is not set correctly.')
            return False
        else:
            for arp_elem in trigger_arp:
                if trigger_arp[arp_elem]:
                    set_arp += ' ' + arp_elem + ' ' + trigger_arp[arp_elem]
        child.sendline(set_arp)
        child.expect('#')
        print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ' + set_arp)
    elif elam_trigger["trigger"]["ip_version"] == '4':
        trigger_l2_l4 = elam_trigger["trigger"]["children"][0]
        set_count = 0
        for pkt_layer in ['l2', 'ipv4', 'l4']:
            set_trigger = ''
            for pkt_elem in trigger_l2_l4[pkt_layer]:
                if trigger_l2_l4[pkt_layer][pkt_elem]:
                    set_trigger += ' ' + pkt_elem + ' ' + trigger_l2_l4[pkt_layer][pkt_elem]
                else:
                    continue
            if set_trigger:
                set_trigger = 'set ' + inner_outer + ' ' + pkt_layer + set_trigger
                child.sendline(set_trigger)
                child.expect('#')
                set_count += 1
                print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ' + set_trigger)
            else:
                print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] No trigger is set for ' + pkt_layer)
        if set_count == 0:
            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Error: No trigger is set for l2-l4.')            
        
    elif elam_trigger["trigger"]["ip_version"] == '6':
        trigger_l2_l4 = elam_trigger["trigger"]["children"][0]
        set_count = 0
        for pkt_layer in ['l2', 'ipv6', 'l4']:
            set_trigger = ''
            for pkt_elem in trigger_l2_l4[pkt_layer]:
                if trigger_l2_l4[pkt_layer][pkt_elem]:
                    set_trigger += ' ' + pkt_elem + ' ' + trigger_l2_l4[pkt_layer][pkt_elem]
                else:
                    continue
            if set_trigger:
                set_trigger = 'set ' + inner_outer + ' ' + pkt_layer + set_trigger
                child.sendline(set_trigger)
                child.expect('#')
                set_count += 1
                print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ' + set_trigger)
            else:
                print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] No trigger is set for ' + pkt_layer)
        if set_count == 0:
            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Error: No trigger is set for l2-l4.') 
        
    else:
        print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Error: IP version must be 4 or 6.')
        return False

    child.sendline('start')
    child.expect('#')
    print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Now ELAM is started on LC' + lc_number + ' ASIC' + asic_number + '!!!!')  
    if 'dump_json_file' in elam_trigger.keys() and elam_trigger['dump_json_file']:
        with open(elam_trigger['dump_json_file'], "w") as outfiles:
            dumped_json_file = elam_trigger.pop('dump_json_file')
            json.dump(elam_trigger, outfiles) 
            print('Saved ELAM parameters to json file ' + dumped_json_file)
    triggered_flag = False    ### This flag becomes True if at least 'Triggered' is detected.
    waiting_time = 0
    while triggered_flag == False and waiting_time <= elam_timeout:
        child.sendline('status')
        child.expect('#')
        status = re.split('[\n\r]+', child.before.decode('utf-8'))[1:-1]
        for line in status:
            if re.search('.*Initialized.*', line):
                print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Error: elam trigger cannot start. Aborted.')
                child.sendline('reset')
                child.expect('#')
                return False
            elif re.search('.*Triggered.*', line):
                triggered_flag = True
                print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ELAM STATUS: ' + ', '.join(status))
                break
            elif re.search('.*Armed.*', line):
                continue
        if triggered_flag == True:    
            trigger_count.value += 1
            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ELAM capture is successfully done!')
            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Downloading ELAM report. . .')
            child.sendline('terminal length 511')
            child.expect('#')
            child.sendline('terminal width 511')
            child.expect('#')

            if asic == 'ns' or asic == 'alp':
                report_cmd = 'report'

            elif float(version) < ereport_supported_version:
                report_cmd = 'report detail'

            else:
                report_cmd = 'ereport'

            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] report type: ' + report_cmd) 
            child.sendline(report_cmd + ' | no-more') 
            try:
                child.expect('module-.*#', timeout=120)
            except:
                print('Error: it took too long to download elam report...')
                return False
            elam_report.extend(re.split('[\n\r]+', child.before.decode('utf-8', errors='ignore'))[1:-1])
            child.sendline('reset')
            child.expect('#')
            child.sendline('end')
            child.expect('#')
            child.sendline('exit')
            child.expect('#')
            child.sendline('exit')
            child.expect('#')
            current_time = time.strftime('%Y-%m-%dT%H-%M-%S', time.localtime())
            if os.path.exists('./elam_report') == False:
                os.mkdir('./elam_report')
            with open('./elam_report/elam_report_' + node_name + '_LC' + lc_number + '_ASIC' + asic_number + '_' + current_time + '.txt', 'w') as out_file:

                if asic == 'ns' or asic == 'alp':
                    i = 0

                else:
                    start_point_flag = False
                    for i, line in enumerate(elam_report):
                        if line.startswith(elam_start_point[report_cmd]):
                            start_point_flag = True
                            break

                    if not start_point_flag : i = 0
                    
                for line in elam_report[i:]:
                    out_file.write(line + '\n')

            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] ELAM GENERATION Completed!')
            return True
            ### escaping from the while loop.
        else:
            print('[' + node_name + ':LC' + lc_number +':ASIC' + asic_number + '] Packet is not captured yet, continue...')
            waiting_time += 5
            time.sleep(5)
    if triggered_flag == False:
        print("Packet is not captured within the timeout value (" + str(elam_timeout) + " sec).")
        child.sendline('reset')
        child.expect('#')

def main():
    try:
        # Input Parameters
        run_at = ''
        apic_ip = ''
        username = ''
        password = ''
        input_json_file = ''
        elam_timeout = 600
        elam_params = {
            "node-name": "",
            "role": "leaf",
            # "asic": "tah",
            "in-select": "",
            "out-select": "1",
            "direction": "",
            # "detail": 'yes',
            # "report-type": "detail",
            # "box": "yes",
            "trigger": {
                "arp": "no",
                "ip_version": "4",
                "children": [
                    {
                        "arp": {
                            "source-ip-addr": "",
                            "source-mac-addr": "",
                            "target-ip-addr": "",
                            "target-mac-addr": ""
                        },
                        "ipv4": {
                            "dst_ip": "",
                            "next-protocol": "",
                            "src_ip": ""
                        },
                        "ipv6": {
                            "dst_ip": "",
                            "src_ip": ""
                        },
                        "l2": {
                            "dst_mac": "",
                            "src_mac": ""
                        },
                        "l4": {
                            "dst-port": "",
                            "src-port": ""
                        }
                    }
                ]
            },
            "dump_json_file": ""
        }
        argv = sys.argv[1:]
        options, arguments = getopt.getopt(argv, "U:P:R:J:T:D:H:N", ['username=', 'password=', 'run-at=', 'apic=', 'json-file=', 'timeout=', 'dump-json=', 'help', 'no-assist'])
    except Exception as e:        
        print('Error: No valid option or argument: {}'.format(e))
        exit()
    else:
        # If this is true, displaying acidiag fnvread, node name check, and auto detection of switch role are enabled.
        enable_assist = True
        
        for opt_name,opt_val in options:
            if opt_name in ('-U', '--username'):
                username = opt_val
            elif opt_name in ('-P', '--password'):
                password = opt_val
            elif opt_name in ('-R', '--run-at'):
                run_at = opt_val
                if run_at != 'client' and run_at != 'apic':
                    print("Option is not correct; Please specify 'client or 'apic'.")
                    exit()
            elif opt_name == '--apic':
                apic_ip = opt_val
            elif opt_name in ('-J', '--json-file'):
                input_json_file = opt_val
            elif opt_name in ('-T', '--timeout'):
                elam_timeout = int(opt_val)
            elif opt_name in ('-D', '--dump-json'):
                if re.search('.json', opt_val) is None:
                    elam_params['dump_json_file'] = opt_val + '.json'
                else:
                    elam_params['dump_json_file'] = opt_val
            elif opt_name in ('-N', '--no-assist'):
                enable_assist = False
            elif opt_name in ('-H', '--help'):
                print("Usage: ")
                print("-U, --username       username used to login to apic")
                print("-P, --password       password used along with username to login to apic")
                print("-R, --run-at         specify where you are running this ELAM command tool. on 'apic' or 'client'")
                print("    --apic           if you run the tool on client, specify apic's IP address at which(its Fabric) you want to take ELAM")
                print("-J, --json-file      if you are familiar with ELAM parameters, you can specify a json file by which advanced options of ELAM can be used")
                print("                     you can find some example at https://gitlab-sjc.cisco.com/japan-tac-aci/elam-tool2/tree/master/trigger_json")
                print("-T, --timeout        specify the time to wait packet to be captured before the tool stops running")
                print("-D, --dump-json      specify filename if you want to create a json file to store entered ELAM parameters")
                print("-N, --no-assist      disable displaying acidiag fnvread, node name check and auto detection of switch role.")
                exit()

    #run_dev = {"run_at": 'client', "apic_ip": 'p3-apic1'}
    #username = 'admin'
    #password = 'ins3965!'
    #'''    
    if not run_at:
        run_at = input('On which platform are you running the script, client or apic? [client/apic]: ')
        while run_at != 'client' and run_at != 'apic':
            run_at = input('answer [client/apic]: ')
        else:
            None
    
    if run_at == 'client':
        if not apic_ip:
            apic_ip = input('APIC IP: ')
        run_dev = {"run_at": run_at, "apic_ip": apic_ip}
    elif run_at == 'apic':
        run_dev = {"run_at": run_at}
    else:
        print('Error: Platform must be either client or apic.')
    #'''

    if not username:    
        username = input('username: ')
    if not password:
        password = getpass.getpass('password: ')
    user_pass = {'username': username, 'password': password}
        
    if input_json_file:
        try:
            with open(input_json_file, 'r') as trigger_json:
            #with open('trigger.json', 'r') as trigger_json:
                elam_trigger = json.loads(trigger_json.read())
        except Exception:
            print('Error: Cannot open the specified file.')
            exit()
    else:
        for k,v in elam_params.items():
            if k == "node-name":
                if enable_assist == True:
                    # Ask whether user want to display node names.
                    view_node_ans = ' '
                    while view_node_ans != 'y' and view_node_ans != 'n' and view_node_ans != '':
                        print('\nAfter this, you need to input node name or node id at which you want to execute ELAM.')
                        view_node_ans = input('Do you want to view the result of \'acidiag fnvread\'? (y/N): ')
                        view_node_ans = view_node_ans.lower()
                        if view_node_ans != 'y' and view_node_ans != 'n' and view_node_ans != '':
                            print('Error: Please input y or n.\n')

                    # Login APIC
                    if run_dev["run_at"] == 'client':
                        child = pexpect.spawn('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=no %s@%s' % (username, run_dev["apic_ip"]), timeout = 60)
                        child.expect('password:')
                        child.sendline(password)
                        child.expect('#')
                    elif run_dev["run_at"] == 'apic':
                        child = pexpect.spawn('zsh', timeout = 60)
                        child.expect('#')
                    
                    # Show acidiag fnvread
                    if view_node_ans == 'y':
                        child.sendline('acidiag fnvread')
                        child.expect('#')
                        for line_num in range(len(child.before.decode('utf-8').splitlines()) - 4):
                            if line_num == 0:
                                print('\n#' + child.before.decode('utf-8').splitlines()[0])
                            else:
                                print(child.before.decode('utf-8').splitlines()[line_num])

                    # Get topSystem MO about leaves and spines
                    child.sendline('moquery -c topSystem -o json -f \'top.System.role=="leaf" or top.System.role=="spine"\'')
                    child.expect('#')
                    mo_topSystem = json.loads(''.join(child.before.decode('utf-8').splitlines()[3:-4]))
                    child.sendline('exit')

                    # Input node name or node id
                    v = input('Enter node name or node id at which you want to execute ELAM: ')
                    while not check_nodename_or_nodeid_validity(v, mo_topSystem):
                        print('Error: Node name or node id is invalid, please enter a valid value.\n')
                        v = input('Enter node name or node id at which you want to execute ELAM: ')
                    # p = re.compile('fab[1-5]-(leaf|spine)[1-9]')

                    # Convert node id to node name
                    for mo_i in range(len(mo_topSystem['imdata'])):
                        if v == str(mo_topSystem['imdata'][mo_i]['topSystem']['attributes']['id']):
                            v = mo_topSystem['imdata'][mo_i]['topSystem']['attributes']['name']
                            break
                else:
                    v = input('Enter node name at which you want to execute ELAM: ')
                print("Node name is " + v)

            elif k == "role":
                if enable_assist == True:
                    # Get node role from topSystem MO
                    for mo_i in range(len(mo_topSystem['imdata'])):
                        if elam_params["node-name"] == str(mo_topSystem['imdata'][mo_i]['topSystem']['attributes']['name']):
                            v = mo_topSystem['imdata'][mo_i]['topSystem']['attributes']['role']
                            break
                    print('Node role is ' + v)
                    
                else:
                    while True:    
                        i = input('Enter role of the node(LEAF | spine): ')
                        if i:
                            v = i.lower()
                        if v != "leaf" and v != "spine":
                            print('Error: Node role is mandatory, please enter a valid value.')
                        else:
                            print('Node role chosen is ' + v)
                            break

                
            # elif k == "asic":
            #     i = input('Enter ASIC family(ns|TAH|roc): ')
            #     if i:
            #         v = i
            #     print('ASIC Family chosen is ' + v)
            #     if v not in ["ns", "tah", "roc"]:
            #         print('Error: ASIC family is mandatory, please enter a valid value.')
            #         exit()
            #     if v == "ns":
            #          i2 = input('Enter direction of packets { INGRESS(packet comes in from front panel ports) | egress(packet was sourced from a fabric port) }: ')
            #          if i2:
            #             elam_params['direction'] = i2
            #          print('Direction chosen is ' + elam_params['direction'])
            elif k == "in-select":
                while True:
                    if elam_params['role'] == "spine":
                        v = "14"
                        print("This is Spine switch, in-select is chosen to " + v)
                        elam_params['direction'] = "ingress"
                        break
                    else:
                        i = input('Choose the packet from 1: Access Port or 2: Fabric Port (1|2): ')
                        if i not in ["1", "2"]:
                            print('Error: Please enter a valid option')
                        else:
                            if i == "1":
                                v = "6"
                                elam_params['direction'] = "ingress"
                            elif i == "2":
                                v = "14"
                                elam_params['direction'] = "egress"
                            print('in-select chosen is ' + v)
                            break
                print('If it is gen1 switch, direction option is chosen as ' + elam_params['direction'])

            # elif k == "out-select":
            #     i = input('Enter out-select option(1): ')
            #     if i:
            #         v = i
            #     print('out-select chosen is ' + v)
            #     if v not in ["0", "1", "2"]:
            #         print('Error: Please enter a valid "out-select" option')
            #         exit()
            elif k == "trigger":
                p_ipv4 = re.compile('^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$')
                p_ipv6 = re.compile('^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$')
                p_mac = re.compile('^([0-9a-fA-F]{4}\.){2}([0-9a-fA-F]{4})$')
                p_port = re.compile('^[0-9]{1,5}$')
                is_arp = ""
                prot_list = []
                while True:
                    print('\n')                        
                    if is_arp == 'y':
                        elam_params['trigger']['arp'] = "yes"                       
                        break
                    elif is_arp == 'n':
                        print('Choose filter protocol type from following options by entering a number of [1|2|3].')
                        print('Multiple protocols can be chosen by entering a comma separated list of numbers.')
                        print('If none of them is chosen (in case of only pressing "Enter" key), no filter will be applied to ELAM. It means any packet will be captured.')
                        print('1: ip')
                        print('2: l2')
                        print('3: l4')
                        i = input(': ')
                        if i:
                            is_valid_prot = True
                            prot_list = i.split(',')
                            for prot in prot_list:
                                if prot not in ["1", "2", "3"]:
                                    print('Error: Please enter one of numbers (1|2|3)')
                                    is_valid_prot = False
                                    break
                            if is_valid_prot == True:
                                break
                            else:
                                continue
                        else:
                            print('No filter is chosen')
                            break
                    else:
                        is_arp = input('Do you want to capture a ARP packet? (y/n): ')
                        continue
                
                if is_arp == "y":
                    while True:
                        v['children'][0]['arp']['target-ip-addr'] = input("Enter ARP target IP address: ")
                        if v['children'][0]['arp']['target-ip-addr']:
                            r1 = p_ipv4.match(v['children'][0]['arp']['target-ip-addr'])
                            if r1 is None:
                                print("ERROR: Target IP address format is not correct. Please check")
                            else:
                                print('Target IP is ' + v['children'][0]['arp']['target-ip-addr'])
                                break
                        else:
                            break
                            
                    while True:
                        v['children'][0]['arp']['source-ip-addr'] = input("Enter ARP source IP address: ")
                        if v['children'][0]['arp']['source-ip-addr']:
                            r2 = p_ipv4.match(v['children'][0]['arp']['source-ip-addr'])
                            if r2 is None:
                                print("ERROR: Source IP address format is not correct. Please check")
                            else:
                                print('Source IP is ' + v['children'][0]['arp']['source-ip-addr'])
                                break
                        else:
                            break

                    while True:
                        v['children'][0]['arp']['target-mac-addr'] = input("Enter ARP target MAC address (use xxxx.xxxx.xxxx format): ")
                        if v['children'][0]['arp']['target-mac-addr']:
                            r3 = p_mac.match(v['children'][0]['arp']['target-mac-addr'])
                            if r3 is None:
                                print("ERROR: Target MAC address format is not correct. Please check")
                            else:
                                print('Target MAC is ' + v['children'][0]['arp']['target-mac-addr'])
                                break
                        else:
                            break
                    
                    while True:
                        v['children'][0]['arp']['source-mac-addr'] = input("Enter ARP source MAC address (use xxxx.xxxx.xxxx format): ")
                        if v['children'][0]['arp']['source-mac-addr']:
                            r4 = p_mac.match(v['children'][0]['arp']['source-mac-addr'])
                            if r4 is None:
                                print("ERROR: Source MAC address format is not correct. Please check")
                            else:
                                print('Source MAC is ' + v['children'][0]['arp']['source-mac-addr'])
                                break
                        else:
                            break
                else:
                    if "1" in prot_list:
                        while True:
                            dst_ip = input("Enter destination IPv4 or IPv6 address: ")
                            if dst_ip:
                                if p_ipv4.match(dst_ip) is not None:
                                    v['children'][0]['ipv4']['dst_ip'] = dst_ip
                                    print('Destination IPv4 is ' + v['children'][0]['ipv4']['dst_ip'])
                                    break
                                elif p_ipv6.match(dst_ip) is not None:
                                    v['children'][0]['ipv6']['dst_ip'] = dst_ip
                                    v['ip_version'] = '6'
                                    print('Destination IPv6 is ' + v['children'][0]['ipv6']['dst_ip'])
                                    break
                                else:
                                    print("ERROR: Destination IP address format is not correct. Please check")
                            else:
                                break

                        while True:
                            src_ip = input("Enter source IPv4 or IPv6 address: ")
                            if src_ip:
                                if p_ipv4.match(src_ip) is not None:
                                    v['children'][0]['ipv4']['src_ip'] = src_ip
                                    print('Source IPv4 is ' + v['children'][0]['ipv4']['src_ip'])
                                    break
                                elif p_ipv6.match(src_ip) is not None:
                                    v['children'][0]['ipv6']['src_ip'] = src_ip
                                    v['ip_version'] = '6'
                                    print('Source IPv6 is ' + v['children'][0]['ipv6']['src_ip'])
                                    break
                                else:
                                    print("ERROR: Source IP address format is not correct. Please check")
                            else:
                                break
                    if "2" in prot_list:
                        while True:
                            v['children'][0]['l2']['dst_mac'] = input("Enter destination MAC address (use xxxx.xxxx.xxxx format): ")
                            if v['children'][0]['l2']['dst_mac']:
                                r1 = p_mac.match(v['children'][0]['l2']['dst_mac'])
                                if r1 is None:
                                    print("ERROR: Destination MAC address format is not correct. Please check")
                                else:
                                    print('Destination MAC is ' + v['children'][0]['l2']['dst_mac'])
                                    break
                            else:
                                break

                        while True:
                            v['children'][0]['l2']['src_mac'] = input("Enter source MAC address (use xxxx.xxxx.xxxx format): ")
                            if v['children'][0]['l2']['src_mac']:
                                r2 = p_mac.match(v['children'][0]['l2']['src_mac'])
                                if r2 is None:
                                    print("ERROR: Source MAC address format is not correct. Please check")
                                else:
                                    print('Source MAC is ' + v['children'][0]['l2']['src_mac'])
                                    break
                            else:
                                break
                    if "3" in prot_list:
                        while True:
                            v['children'][0]['l4']['dst-port'] = input("Enter destination port: ")
                            if v['children'][0]['l4']['dst-port']:
                                r1 = p_port.match(v['children'][0]['l4']['dst-port'])
                                if r1 is None:
                                    print("ERROR: Destination port format is not correct. Please enter port number in range of [1-65535]")
                                else:
                                    print('Destination port is ' + v['children'][0]['l4']['dst-port'])
                                    break
                            else:
                                break

                        while True:
                            v['children'][0]['l4']['src-port'] = input("Enter source port: ")
                            if v['children'][0]['l4']['src-port']:
                                r2 = p_port.match(v['children'][0]['l4']['src-port'])
                                if r2 is None:
                                    print("ERROR: Source port format is not correct. Please enter port number in range of [1-65535]")
                                else:
                                    print('Source port is ' + v['children'][0]['l4']['src-port'])
                                    break
                            else:
                                break
                        
            elif k == "dump_json_file":
                if v:
                    print('Will try to save ELAM parameters to ' + v)
                else:
                    i = input('Do you want to create a json file locally to store the ELAM parameters you entered (y|N): ')
                    if i == 'y':
                        i2 = input('Enter the json filename you want to create: ')
                        if re.search('.json', i2) is None:
                            v = i2 + '.json'
                        else:
                            v = i2
                    else:
                        print('Will NOT save json file for entered ELAM parameters')

            elam_params[k] = v

        elam_trigger = elam_params
    
    get_elam_report(run_dev, user_pass, elam_trigger, elam_timeout)

if __name__ == '__main__':
    main()
