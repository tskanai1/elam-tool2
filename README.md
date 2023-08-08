# ACI ELAM CLI Tool to easily use ELAM
# Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
   1. [How to install on your local machine](#installlocal)
   2. [How to install on your APIC](#installapic)
   3. [How to uninstall on your APIC](#uninstallapic)
3. [How to use for single switch (leaf/spine)](#howtousesingle)
   1. [Interactive way (by default)](#singleinteractive)
   2. [Using json file (avoid typing the same parameters again and again)](#singlejson)
4. [How to use for multiple switches](#howtousemultiple)
   1. [Interactive way](#multiinteractive)
   2. [Using json file](#multijson)

## Introduction <a name="introduction"></a>
We, ACI TAC engineers, often collect ELAM reports from our lab devices or from our customer's devices to troubleshoot packet forwarding issues. Although ELAM is strong tool and very useful for such troubleshooting scenarios, we have some difficulties below.
- It is complicated and requires some knowledges/experiences regarding ELAM parameters to set/trigger ELAM and collect ELAM reports, which may be difficult for junior ACI engineers
- Although we have a great [ELAM Assistant](https://dcappcenter.cisco.com/elam-assistant.html) App which allows us to easily execute ELAM and decode the result, some customers (typically in Japan) refuse to install an App on their production ACI fabric. Those customers tend to refuse Webex access to their devices for troubleshooting. We need to tell those customers ELAM commands including parameters to filter packet flows we are focusing on.

With that said, we indeed have some demands for CLI tool which enables ACI users to easily set/trigger ELAM and collect ELAM reports without knowledge about ELAM parameters such as ASIC family names, in-select/out-select, etc. You will be able to use this tool by following [Installation](#installation) and How to use sections below.

## Installation <a name="installation"></a>
You can run this tool on your local machine (client) or on an APIC. If Python 3.10 is installed on your local machine, it is recommended to run this tool on your local machine since installation is much easier and you can run the tool against any ACI fabric as long as  your local machine has connectivity with an APIC in the fabric.
### How to install on your local machine <a name="installlocal"></a>
Requirement: Python version should be 3.10 or later.
Just execute the following command to install the tool.
```
$ pip install git+https://github.com/tskanai1/elam-tool2.git
Collecting git+https://github.com/tskanai1/elam-tool2.git
----- snip -----
Building wheels for collected packages: elam-tool2
----- snip -----
Successfully built elam-tool2
Installing collected packages: elam-tool2
Successfully installed elam-tool2-1.2.0
```
Then, you can use two elam commands, elam_multi_dev and elam_report_generator.
```
$ elam_<TAB><TAB>
elam_multi_dev         elam_report_generator
```

### How to install on your APIC <a name="installapic"></a>
Download [the elam-tool2's package](https://gitlab-sjc.cisco.com/japan-tac-aci/elam-tool2/-/archive/master/elam-tool2-master.zip) and put the zip file onto home directory on your APIC.  
Unzip the file and execute ```setup_on_apic.sh``` script to install the tool.
```
fab3-apic1# bash
admin@fab3-apic1:~> unzip elam-tool2-master.zip
Archive:  elam-tool2-master.zip
13faf2603970ac5e8f13f35519b072428a809c07
   creating: elam-tool2-master/
 extracting: elam-tool2-master/.gitignore
  inflating: elam-tool2-master/README.md
   creating: elam-tool2-master/elam_tool2/
 extracting: elam-tool2-master/elam_tool2/__init__.py
  inflating: elam-tool2-master/elam_tool2/elam_multi_dev.py
  inflating: elam-tool2-master/elam_tool2/elam_report_generator.py
----- snip -----
admin@fab3-apic1:~> cd elam-tool2-master
admin@fab3-apic1:elam-tool2-master> ./setup_on_apic.sh
### Setup elam-tool2 on APIC ...
### Installing pexpect-4.8.0 ...
----- snip -----
### Installed packages are:
pexpect  pexpect-4.8.0-py3.7.egg-info  ptyprocess  ptyprocess-0.7.0-py3.7.egg-info
### Setup is completed!
```
Then you can use the tool as follows.
```
admin@fab3-apic1:elam-tool2-master> python3 elam_tool2/elam_report_generator.py
On which platform are you running the script, client or apic? [client/apic]:
----- snip -----
```
How to use the tool on APIC is the same as on client except that you need to type ```python3``` before the command.

### How to uninstall on your APIC <a name="uninstallapic"></a>
When you want to uninstall the python script and the installed packages from the APIC, just execute the ```uninstall_on_apic.sh``` under the elam-tool2-master directory.
```
fab3-apic1# bash
admin@fab3-apic1:~> cd elam-tool2-master
admin@fab3-apic1:elam-tool2-master> ./uninstall_on_apic.sh
### Uninstall elam-tool2 on APIC ...
### Uninstalling pexpect-4.8.0 ...
/usr/lib64/python3.7/distutils/dist.py:274: UserWarning: Unknown distribution option: 'install_requires'
  warnings.warn(msg)
running install
running build
running build_py
running install_lib
running install_egg_info
Removing /home/admin/.local/lib/python3.7/site-packages/pexpect-4.8.0-py3.7.egg-info
Writing /home/admin/.local/lib/python3.7/site-packages/pexpect-4.8.0-py3.7.egg-info
writing list of installed files to 'pexpect_list.txt'
### Uninstalling ptyprocess-0.7.0 ...
running install
running build
running build_py
running install_lib
running install_egg_info
Removing /home/admin/.local/lib/python3.7/site-packages/ptyprocess-0.7.0-py3.7.egg-info
Writing /home/admin/.local/lib/python3.7/site-packages/ptyprocess-0.7.0-py3.7.egg-info
writing list of installed files to 'ptyprocess_list.txt'
### Remove elam-tool2 directory
### No packages should be here:
### Uninstall elam-tool2 is completed!
admin@fab3-apic1:elam-tool2-master>
```

## How to use for single switch (leaf/spine) <a name="howtousesingle"></a>
### Interactive way (by default) <a name="singleinteractive"></a>
Just execute ```elam_report_generator``` command. Then, the tool asks you each required parameter in an interactive way.
```
$ elam_report_generator
On which platform are you running the script, client or apic? [client/apic]: client
APIC IP: f3a1
username: admin
password:

After this, you need to input node name or node id at which you want to execute ELAM.
Do you want to view the result of 'acidiag fnvread'? (y/N): y

# acidiag fnvread

      ID   Pod ID                 Name    Serial Number         IP Address    Role        State   LastUpdMsgId
--------------------------------------------------------------------------------------------------------------
     103        1           fab3-leaf3      FDO21162J7H     10.0.136.65/32    leaf         active   0
     104        1           fab3-leaf4      FDO21162HY8     10.0.136.64/32    leaf         active   0
     106        1           fab3-leaf6      FDO203202BN      10.0.248.1/32    leaf         active   0
     107        1           fab3-leaf7      FDO203202GG      10.0.96.64/32    leaf         active   0
     108        1           fab3-leaf8      FDO203308DH      10.0.96.65/32    leaf         active   0
     109        1           fab3-leaf9      FDO211622DM      10.0.248.0/32    leaf         active   0
     201        1       fab3-p1-spine1      FOX1821GYQG     10.0.248.30/32   spine         active   0
    1105        1           fab3-leaf5      FDO20340CEG     10.0.136.66/32    leaf         active   0
    2101        2        fab3-p2-leaf1      FDO211506NJ      20.0.96.64/32    leaf         active   0
    2102        2        fab3-p2-leaf2      FDO21141MY3      20.0.56.64/32    leaf         active   0
    2201        2       fab3-p2-spine1      FDO2218068B      20.0.248.0/32   spine         active   0

Total 11 nodes

Enter node name or node id at which you want to execute ELAM: 103
Node name is fab3-leaf3
Node role is leaf
Choose the packet from 1: Access Port or 2: Fabric Port (1|2): 1
in-select chosen is 6
If it is gen1 switch, direction option is chosen as ingress
```

If you like to capture an ARP packet, you can set parameters like target IP, source IP, target MAC and source MAC addresses.
```
Do you want to capture a ARP packet? (y/n): y


Enter destination IP address: 192.168.22.1
Destination IP is 192.168.22.1
Enter source IP address: 192.168.21.1
Source IP is 192.168.21.1
```

If not ARP packet, you can choose one or more protocols within l2-l4 layers. All the protocols (```1,2,3```) are chosen in an example below, then you can set parameters for each layer.
```
Do you want to capture a ARP packet? (y/n): n


Choose filter protocol type from following options by entering a number of [1|2|3].
Multiple protocols can be chosen by entering a comma separated list of numbers.
If none of them is chosen (in case of only pressing "Enter" key), no filter will be applied to ELAM. It means any packet will be captured.
1: ip
2: l2
3: l4
: 1,2,3
Enter destination IPv4 or IPv6 address: 192.168.22.1
Destination IPv4 is 192.168.22.1
Enter source IPv4 or IPv6 address:
Enter destination MAC address (use xxxx.xxxx.xxxx format):
Enter source MAC address (use xxxx.xxxx.xxxx format): 0035.1aef.cbb7
Source MAC is 0035.1aef.cbb7
Enter destination port: 22
Destination port is 22
Enter source port:
```

After it is determined if a json file containing parameters you entered is saved or not, elam process starts.
```
Do you want to create a json file locally to store the ELAM parameters you entered (y|N): y  <<== If you choose y, json file which contains parameters you specified will be created and can be used later. See the next section for detail.
Enter the json filename you want to create: node-103_test.json
apic login
switch fab3-leaf3 login
Identified as box-type switch
[fab3-leaf3:LC1:ASIC0] debug platform internal tah elam asic0
[fab3-leaf3:LC1:ASIC0] trigger init in-select 6 out-select 1
[fab3-leaf3:LC1:ASIC0] ELAM trigger is successfully reset.
[fab3-leaf3:LC1:ASIC0] set outer l2 src_mac 0035.1aef.cbb7
[fab3-leaf3:LC1:ASIC0] set outer ipv4 dst_ip 192.168.22.1
[fab3-leaf3:LC1:ASIC0] set outer l4 dst-port 22
[fab3-leaf3:LC1:ASIC0] Now ELAM is started on LC1 ASIC0!!!!
Saved ELAM parameters to json file node-103_test.json
[fab3-leaf3:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3:LC1:ASIC0] ELAM STATUS:  ELAM STATUS, ===========, Asic 0 Slice 0 Status Armed, Asic 0 Slice 1 Status Triggered
[fab3-leaf3:LC1:ASIC0] ELAM capture is successfully done!
[fab3-leaf3:LC1:ASIC0] Downloading ELAM report. . .
[fab3-leaf3:LC1:ASIC0] report type: ereport
[fab3-leaf3:LC1:ASIC0] ELAM GENERATION Completed!
The script completed to generate ELAM report !!!!!!!!
```
elam is executed on each ASIC on each LC in parallel using multiprocessing technique in Python. (Ex. if you run the tool against modular spine with two LC's and each LC has 4 ASIC's, 2x4 = 8 processes will run at the same time.)
While elam status is Armed on all the ASIC's, the tool continues to run and regularly check the elam status. Once the status gets Triggered on at least one ASIC, it collects elam report (ereport is used if supported) and stored it as a file under elam_report directory under your current directory and process for ASIC with Armed status is automatically terminated if any. The file name starts with elam_report and contains node name, LC#, ASIC# as well as timestamp when it is collected.
```
$ ls elam_report/
elam_report_fab3-leaf3_LC1_ASIC0_2022-04-20T21-02-53.txt
$ head -50 elam_report/elam_report_fab3-leaf3_LC1_ASIC0_2022-04-20T21-02-53.txt
 ELAM REPORT
======================================================================================================================================================
                                                        Trigger/Basic Information
======================================================================================================================================================
ELAM Report File                        : /tmp/logs/elam_2022-04-20-02m-12h-50s.txt
In-Select Trigger                       : Outerl2-outerl3-outerl4( 6 )
Out-Select Trigger                      : Pktrw-sideband-drpvec( 1 )
ELAM Captured Device                    : LEAF
Packet Direction                        : ingress
Triggered ASIC type                     : Sugarbowl
Triggered ASIC instance                 : 0
Triggered Slice                         : 1
Incoming Interface                      : 0x20( 0x20 )
( Slice Source ID(Ss) in "show plat int hal l2 port gpd" )
======================================================================================================================================================
                                                            Captured Packet
======================================================================================================================================================
------------------------------------------------------------------------------------------------------------------------------------------------------
Outer Packet Attributes
------------------------------------------------------------------------------------------------------------------------------------------------------
Outer Packet Attributes       : l2uc ipv4 ip ipuc ipv4uc tcp
Opcode                        : OPCODE_UC
------------------------------------------------------------------------------------------------------------------------------------------------------
Outer L2 Header
------------------------------------------------------------------------------------------------------------------------------------------------------
Destination MAC               : 0022.BDF8.19FF
Source MAC                    : 0035.1AEF.CBB7
802.1Q tag is valid           : yes( 0x1 )
CoS                           : 0( 0x0 )
Access Encap VLAN             : 2001( 0x7D1 )
------------------------------------------------------------------------------------------------------------------------------------------------------
Outer L3 Header
------------------------------------------------------------------------------------------------------------------------------------------------------
L3 Type                       : IPv4
IP Version                    : 4
DSCP                          : 0
IP Packet Length              : 60 ( = IP header(28 bytes) + IP payload )
Don't Fragment Bit            : not set
TTL                           : 64
IP Protocol Number            : TCP
IP CheckSum                   : 15644( 0x3D1C )
Destination IP                : 192.168.22.1
Source IP                     : 192.168.21.1
------------------------------------------------------------------------------------------------------------------------------------------------------
Outer L4 Header
------------------------------------------------------------------------------------------------------------------------------------------------------
L4 Type                       : TCP
Source Port                   : 58715( 0xE55B )
Destination Port              : 22( 0x16 )
TCP/UDP CheckSum              : 0xDF96( 0xDF96 )
```
You can specify uesrname and password to login APIC, [client or apic] where you run the tool, and APIC's IP/hostname if you run on client, as arguments for elam_report_generator command as follows. These options may be useful if you run the tool for the same ACI fabric multiple times.
```
$ elam_report_generator --username admin --password XXXXX --run-at client --apic f3a1

After this, you need to input node name or node id at which you want to execute ELAM.
Do you want to view the result of 'acidiag fnvread'? (y/N):
Enter node name or node id at which you want to execute ELAM: fab3-leaf3
Node name is fab3-leaf3
Node role is leaf
Choose the packet from 1: Access Port or 2: Fabric Port (1|2):
```
All the options and its description can be checked by ```--help``` option as follows.
```
$ elam_report_generator --help
Usage:
-U, --username       username used to login to apic
-P, --password       password used along with username to login to apic
-R, --run-at         specify where you are running this ELAM command tool. on 'apic' or 'client'
    --apic           if you run the tool on client, specify apic's IP address at which(its Fabric) you want to take ELAM
-J, --json-file      if you are familiar with ELAM parameters, you can specify a json file by which advanced options of ELAM can be used
                     you can find some example at https://gitlab-sjc.cisco.com/japan-tac-aci/elam-tool2/tree/master/trigger_json
-T, --timeout        specify the time to wait packet to be captured before the tool stops running
-D, --dump-json      specify filename if you want to create a json file to store entered ELAM parameters
-N, --no-assist      disable displaying acidiag fnvread, node name check and auto detection of switch role.
```

### Using json file (avoid typing the same parameters again and again) <a name="singlejson"></a>
We sometimes collect elam report multiple times for the single packet flow using the same elam parameters, and it wastes time to manually type the same parameters again and again. As a solution for that, this tool can dump json file containing elam parameters when you run the tool in an interactive way. Following json file is the one which was created in an example above.
```
$ cat node-103_test.json
{"node-name": "fab3-leaf3", "role": "leaf", "in-select": "6", "out-select": "1", "direction": "ingress", "trigger": {"arp": "no", "ip_version": "4", "children": [{"arp": {"source-ip-addr": "", "source-mac-addr": "", "target-ip-addr": "", "target-mac-addr": ""}, "ipv4": {"dst_ip": "192.168.22.1", "next-protocol": "", "src_ip": ""}, "ipv6": {"dst_ip": "", "src_ip": ""}, "l2": {"dst_mac": "", "src_mac": "0035.1aef.cbb7"}, "l4": {"dst-port": "22", "src-port": ""}}]}}
```

The json file can be specified by ```-J``` or ```--json-file``` option when you run the tool again. Using json file and the options above will save your time a lot! Following is an example output when using the json file and login options. You don't need to type any parameter in this mode.
```
$ elam_report_generator --username admin --password XXXXX --run-at client --apic f3a1 --json-file node-103_test.json
apic login
switch fab3-leaf3 login
Identified as box-type switch
[fab3-leaf3:LC1:ASIC0] debug platform internal tah elam asic0
[fab3-leaf3:LC1:ASIC0] trigger init in-select 6 out-select 1
[fab3-leaf3:LC1:ASIC0] ELAM trigger is successfully reset.
[fab3-leaf3:LC1:ASIC0] set outer l2 src_mac 0035.1aef.cbb7
[fab3-leaf3:LC1:ASIC0] set outer ipv4 dst_ip 192.168.22.1
[fab3-leaf3:LC1:ASIC0] set outer l4 dst-port 22
[fab3-leaf3:LC1:ASIC0] Now ELAM is started on LC1 ASIC0!!!!
[fab3-leaf3:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3:LC1:ASIC0] ELAM STATUS:  ELAM STATUS, ===========, Asic 0 Slice 0 Status Armed, Asic 0 Slice 1 Status Triggered
[fab3-leaf3:LC1:ASIC0] ELAM capture is successfully done!
[fab3-leaf3:LC1:ASIC0] Downloading ELAM report. . .
[fab3-leaf3:LC1:ASIC0] report type: ereport
[fab3-leaf3:LC1:ASIC0] ELAM GENERATION Completed!
The script completed to generate ELAM report !!!!!!!!
```

## How to use for multiple switches <a name="howtousemultiple"></a>
### Interactive way <a name="multiinteractive"></a>
Just run the script above for each leaf/spine in the packet path.
### Using json file <a name="multijson"></a>
If you prepare for a json file which contains a list of objects for elam parameters on each node, you can run the elam tool on multiple switches in parallel.  
Following is an example json file trigger_json/sample_for-elam_multi_dev.json under this gitlab project which triggers a packet from 192.168.21.1 to 192.168.22.1 passing through fab3-leaf3 as an ingress leaf and fab3-leaf8 as an egress leaf. You can customize each parameter to match your environment.
```
$ cat trigger_json/sample_for-elam_multi_dev.json
[
    {
	"node-name": "fab3-leaf3",
	"role": "leaf",
	"direction": "ingress",
	"in-select": "6",
	"out-select": "1",
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
			"dst_ip": "192.168.22.1",
			"next-protocol": "1",
			"src_ip": "192.168.21.1"
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
	}
    },
    {
	"node-name": "fab3-leaf8",
	"role": "leaf",
	"direction": "egress",
	"in-select": "7",
	"out-select": "1",
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
			"dst_ip": "192.168.22.1",
			"next-protocol": "1",
			"src_ip": "192.168.21.1"
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
	}
    }
]
```

When you want to run the tool on multiple switches, use ```elam_multi_dev``` command with a json file as an argument. elam will run on each node in parallel using multiprocessing.
```
$ elam_multi_dev trigger_json/sample_all-parameters.json
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
apic login
apic login
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
switch fab3-leaf3 login
switch fab3-leaf8 login
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
Identified as box-type switch
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
Identified as box-type switch
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf3:LC1:ASIC0] debug platform internal tah elam asic0
[fab3-leaf3:LC1:ASIC0] trigger init in-select 6 out-select 1
[fab3-leaf3:LC1:ASIC0] ELAM trigger is successfully reset.
[fab3-leaf3:LC1:ASIC0] No trigger is set for l2
[fab3-leaf3:LC1:ASIC0] set outer ipv4 dst_ip 192.168.22.1 next-protocol 1 src_ip 192.168.21.1
[fab3-leaf3:LC1:ASIC0] No trigger is set for l4
[fab3-leaf3:LC1:ASIC0] Now ELAM is started on LC1 ASIC0!!!!
[fab3-leaf3:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf8:LC1:ASIC0] debug platform internal tah elam asic0
[fab3-leaf8:LC1:ASIC0] trigger init in-select 7 out-select 1
[fab3-leaf8:LC1:ASIC0] ELAM trigger is successfully reset.
[fab3-leaf8:LC1:ASIC0] No trigger is set for l2
[fab3-leaf8:LC1:ASIC0] set inner ipv4 dst_ip 192.168.22.1 next-protocol 1 src_ip 192.168.21.1
[fab3-leaf8:LC1:ASIC0] No trigger is set for l4
[fab3-leaf8:LC1:ASIC0] Now ELAM is started on LC1 ASIC0!!!!
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf8:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf8:LC1:ASIC0] Packet is not captured yet, continue...
[fab3-leaf3:LC1:ASIC0] ELAM STATUS:  ELAM STATUS, ===========, Asic 0 Slice 0 Status Armed, Asic 0 Slice 1 Status Triggered
[fab3-leaf3:LC1:ASIC0] ELAM capture is successfully done!
[fab3-leaf3:LC1:ASIC0] Downloading ELAM report. . .
[fab3-leaf3:LC1:ASIC0] report type: ereport
[fab3-leaf3] process is still alive.
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf8:LC1:ASIC0] ELAM STATUS:  ELAM STATUS, ===========, Asic 0 Slice 0 Status Triggered, Asic 0 Slice 1 Status Triggered
[fab3-leaf8:LC1:ASIC0] ELAM capture is successfully done!
[fab3-leaf8:LC1:ASIC0] Downloading ELAM report. . .
[fab3-leaf8:LC1:ASIC0] report type: ereport
[fab3-leaf3:LC1:ASIC0] ELAM GENERATION Completed!
The script completed to generate ELAM report !!!!!!!!
[fab3-leaf3] process is done!
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf3] process is done!
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf3] process is done!
[fab3-leaf8] process is still alive.
(multiprocessing) There is at least one active process. Continue...
[fab3-leaf8:LC1:ASIC0] ELAM GENERATION Completed!
The script completed to generate ELAM report !!!!!!!!
[fab3-leaf3] process is done!
[fab3-leaf8] process is done!
```
elam_report files are downloaded under elam_report directory in the same manner as a single switch example.
```
$ ls elam_report/
elam_report_fab3-leaf3_LC1_ASIC0_2022-04-13T15-01-44.txt
elam_report_fab3-leaf8_LC1_ASIC0_2022-04-13T15-01-59.txt
```
