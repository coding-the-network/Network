import time, re
from Network.utils import ssh_string_cleaner, input_check
from Network.Constants import *
from collections import namedtuple


class ssh_functions:
    """
    This class is used for storing all available ssh functions for catalyst switches

    """

    @staticmethod
    def __sender(ssh_client, command, terminal, splitter: str = "\r\n", split_type: str = "SPACE", sleep=3):
        """
        This functions gets ssh output and convert it to usable list.

        Parameters
        ----------
        ssh_client : paramiko.SSHClient
                This parameter is connection to destination device
        command : str
                This parameter will be used to send specified command to ssh session
        terminal : str
                Used to make terminal length 0
        splitter : str
                This variable is used for splitting the multiline ssh_output.By default
            '\r\n' is used because Cisco uses '\r\n' for new line.
        split_type : str
                This variable is used for splitting lines produced by splitter split.There
            are three possible choice.
                SPACE-->split by ' ' and removes all ' ' from elements
                2+SPACE-->split by if two or more spaces exist in string and removes ' '
                    from elements
                COMMA-->split by ',' and strips the elements
                COLON-->split by ':' and strips the elements

        sleep : int
                This variable specify how long code should wait to get
            response from socket.

        Returns
        -------
        list1 : list
        """
        ssh_client.send(terminal)
        ssh_client.send(command)
        time.sleep(sleep)
        output = bytes.decode(ssh_client.recv(5000000))
        list1 = ssh_string_cleaner(output, command, splitter, split_type)
        return list1

    @staticmethod
    def get_mac_table(ssh_client=None):
        """
        This function gets 'show mac address-table' and parse the output returned

        If first parameter in line is between 1-4094, then comprehension takes that line list. Later, since
        output format is same on all Catalyst Switches, get first,second and last item from line. Remember
        by default __sender functions uses "SPACE" splitting for every line.
        Parameters
        ----------
        ssh_client

        Returns
        -------
        dict_list : list(namedtuple)
                This list contains named tuples for all MAC addresses in system.Namedtuple variables are
            below.
                Vlan-->str
                MAC-->str
                Port-->str
        """
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWMAC, CISCO_CLI_TERMINAL, sleep=10)
            named_tuple = namedtuple('MACTable', ['Vlan', 'MAC', 'Port'])
            list1 = [m if re.match("^[1-4]?[0-9]?[0-9]?[0-9]$", m[0]) else m[1:] for m in list1 if len(m) > 3]
            dict_list = [named_tuple(m[0], m[1], m[-1]) for m in list1 if len(m) > 3
                         if m[2].upper() == "DYNAMIC" or m[2].upper() == "STATIC"]
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_auth_session(ssh_client=None, auth_session_id="N/A"):
        """
        This function gets 'show authentication sessions' and parse the output returned.

        If 'dot1x' or 'mab' in line, use that parsed line to find out necessary parameters since
        output format is same on all Catalyst Switches

        Parameters
        ----------
        ssh_client

        Returns
        -------
        dict_list : list(namedtuple)
                This list contains named tuples for all dot1x auth sessions in system.Namedtuple variables are
            below.
                Port-->str
                MAC-->str
                AuthType-->str
                Domain-->str
                AuthStatus-->str
                ID-->str
        """
        if ssh_client:
            if (auth_session_id == "N/A"):
                list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWAUTH, CISCO_CLI_TERMINAL, sleep=12)
                named_tuple = namedtuple('AuthSessions', ['Port', 'MAC', 'AuthType', 'Domain', 'AuthStatus', 'ID'])
                dict_list = [named_tuple(m[0], m[1], m[2], m[3], m[4], m[5]) for m in list1 if len(m) == 6 if
                             m[2] == "dot1x" or m[2] == "mab"]
                return dict_list
            else:
                dict_list = []
                list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWAUTH_DETAIL % auth_session_id,
                                               CISCO_CLI_TERMINAL, sleep=3)
                named_tuple = namedtuple('AuthSessionDetail',
                                         ['Port', 'MAC', 'IPv4', 'User', 'Domain', 'ACL', 'Vlan',
                                          'Method'])
                interface, mac, ipv4, username, domain, acl, vlan, method = "", "", "", "", "", "", "", ""
                for index, line in enumerate(list1[:-1]):
                    if ("No sessions match supplied criteria" in line):
                        interface, mac, ipv4, username = "No Session", "No Session", "No Session", "No Session"
                        domain, acl, vlan, method = "No Session", "No Session", "No Session", "No Session"
                        break
                    # print(line)
                    if ("Interface:" in line):
                        interface = line.split(":")[-1].replace(" ", "")
                    if ("MAC Address:" in line):
                        mac = line.split(":")[-1].replace(" ", "")
                    if ("IPv4 Address:" in line):
                        ipv4 = line.split(":")[-1].replace(" ", "")
                    if ("User-Name:" in line):
                        username = line.split(":")[-1].replace(" ", "")
                    if ("Domain:" in line):
                        domain = line.split(":")[-1].replace(" ", "")
                    if ("Vlan Group:" in line):
                        vlan = line.split(":")[-1].replace(" ", "")
                    if ("ACS ACL:" in line):
                        acl = line.split(":")[-1].replace(" ", "")
                    if ("Method" in line and "State" in line):
                        while ("Success" not in line):
                            index += 1
                            if ("Success" in list1[index]):
                                method = list1[index].replace(" ", "").replace("AuthcSuccess", "")
                                break
                            if (len(list1[:-1]) == index):
                                break
                dict_list.append(named_tuple(interface, mac, ipv4, username, domain, acl, vlan, method))
                return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_cdp_neighbors(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWCDP, CISCO_CLI_TERMINAL, split_type="COMMA")
            # print(list1)
            dict_list = []
            named_tuple = namedtuple('CDPNeighbors', ['CDPNeighbor', 'CDPNeighborIP', 'CDPNeighborPlatfrom',
                                                      'CDPNeighborLocalInterface', 'CDPNeighborRemoteInterface'])
            for index, line in enumerate(list1[:-1]):
                if (list(filter(lambda k: re.match("device.*id:.*", k.lower()), line))):
                    cdp_neighbor_IP, cdp_neighbor_platform, cdp_neighbor_localPort, cdp_neighbor_remotePort = "", "", "", ""
                    cdp_neighbor = line[0].split(":")[1].strip()
                    for line2 in range(index + 1, len(list1) - 1):
                        if (list(filter(lambda k: re.match("device.*id:.*", k.lower()), list1[line2]))):
                            break
                        if (list(filter(lambda k: re.match("ip.*address:.*", k.lower()), list1[line2]))):
                            cdp_neighbor_IP = list1[line2][0].split(":")[1].strip()
                        if (list(filter(lambda k: re.match("platform:.*", k.lower()), list1[line2]))):
                            cdp_neighbor_platform = list1[line2][0].split(":")[1].strip()
                        if (list(filter(lambda k: re.match("interface:.*", k.lower()), list1[line2]))):
                            cdp_neighbor_localPort = list1[line2][0].split(":")[1].strip()
                            cdp_neighbor_remotePort = list1[line2][1].split(":")[1].strip()
                    dict_list.append(
                        named_tuple(cdp_neighbor, cdp_neighbor_IP, cdp_neighbor_platform, cdp_neighbor_localPort,
                                    cdp_neighbor_remotePort))

            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_power_inline(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWPOWERINLINE, CISCO_CLI_TERMINAL, sleep=5)
            named_tuple = namedtuple('POE', ['Port', 'AdminStatus', 'OperationalStatus', 'Power'])
            dict_list = [named_tuple(m[0], m[1], m[2], m[3]) for m in list1 if len(m) > 5
                         if (m[1] == "auto" or m[1] == "static")]
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_interface_status(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWINTERFACE, CISCO_CLI_TERMINAL, sleep=10)
            #print(list1)
            named_tuple = namedtuple('InterfaceStatus', ['Port', 'Status', 'Vlan'])
            dict_list=[]
            for m in list1:
                if(len(m)>6):
                    if(m[-5] == "connected" or m[-5] == "notconnec" or m[-5] == "disabled" or m[-5] == "err-disabled" or m[-5] == "sfpAbsent" or m[-5] == "channelDo"):
                        dict_list.append(named_tuple(m[0], m[-5], m[-4]))
                elif(len(m)>5):
                    if (m[-4] == "connected" or m[-4] == "notconnec" or m[-4] == "disabled" or m[-4] == "err-disabled" or m[-4] == "sfpAbsent" or m[-4] == "channelDo"):
                        dict_list.append(named_tuple(m[0], m[-4], m[-3]))
            #dict_list = [named_tuple(m[0], m[-5], m[-4]) for m in list1
            #            if len(m) > 5 if m[-5] == "connected" or m[-5] == "notconnec" or m[-5] == "disabled" or m[
            #                 -5] == "err-disabled" or m[-4] == "connected" or m[-4] == "notconnec" or m[-4] == "disabled" or m[
            #                 -4] == "err-disabled"]
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_stack_status(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWSWITCH, CISCO_CLI_TERMINAL)
            named_tuple = namedtuple('Stack', ['Switch', 'Role', 'Status', 'Priority'])
            dict_list = [named_tuple(m[0].replace("*", ""), m[1], m[-1], m[3]) for m in list1 if len(m) > 5 if
                         m[1] == "Active" or m[1] == "Standby" or m[1] == "Member" or m[1] == "Master"]
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_vrf(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWVRF, CISCO_CLI_TERMINAL)
            #print(list1)
            named_tuple = namedtuple('VRF', ['VRFName'])
            dict_list = [named_tuple(m[0]) for m in list1[1:] if len(m) > 1]
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_vlans(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWVLAN, CISCO_CLI_TERMINAL)
            #print(list1)
            named_tuple = namedtuple('Vlans', ['VlanID', 'VlanName', 'Ports'])
            dict_list = []
            for index, line in enumerate(list1[:-1]):
                if ("active" in line or "act/unsup" in line and len(line) > 2):
                    interfaces = line[3:].copy()
                    for line2 in range(index + 1, len(list1) - 1):
                        # print(list1[line2+1],list1[index])
                        if ("active" in list1[line2] or "act/unsup" in list1[line2]):
                            break
                        else:
                            interfaces += list1[line2]
                    dict_list.append(named_tuple(line[0], line[1], interfaces))
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_inventory(ssh_client=None):
        if ssh_client:
            dict_list = []
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWINVENTORY, CISCO_CLI_TERMINAL, split_type="COMMA")
            named_tuple = namedtuple('Inventory', ['Device', 'SN', 'Name'])
            #print(list1)
            for index, line in enumerate(list1[:-1]):
                for m2 in line:
                    if("PID:" in m2):
                        device=line[0].replace("PID: ","")
                        sn=line[-1].replace("SN: ","")
                        for m3 in list1[index-1]:
                            if("NAME:" in m3):
                                name=list1[index-1][0].replace("NAME: ","").replace('"',"")
                        dict_list.append(named_tuple(device,sn,name))
            #dict_list = [{"Device": m[0], "SN": m[-1]} for m in list1 for m2 in m if "PID:" in m2]
            #dict_list = [named_tuple(list(dict(t).values())[0], list(dict(t).values())[1]) for t in
            #             {tuple(m.items()) for m in dict_list}]
            return dict_list

        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_interface_stats(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWINTERFACESTATS, CISCO_CLI_TERMINAL,
                                           split_type="COMMA")
            #print(list1)
            dict_list = list()
            named_tuple = namedtuple('InterfaceStats', ['Interface', 'InputRate', 'OutputRate', 'CRC'])
            for index, line in enumerate(list1[:-1]):
                if ([k for k in line if re.match("line.*protocol.*is", k)] and len(line) > 1):
                    interface_name = line[0].split(" ")[0]
                    interface_input, interface_output, interface_CRC = "", "", ""
                    for line2 in range(index + 1, len(list1) - 1):
                        if ([k for k in list1[line2] if re.match("line.*protocol.*is", k)] and len(line) > 1):
                            break
                        elif (list(filter(lambda k: re.match(".*input rate.*", k.lower()), list1[line2]))):
                            interface_input = list1[line2][0].split(" ")[-2] + " " + list1[line2][0].split(" ")[-1]
                        elif (list(filter(lambda k: re.match(".*output rate.*", k.lower()), list1[line2]))):
                            interface_output = list1[line2][0].split(" ")[-2] + " " + list1[line2][0].split(" ")[-1]
                        elif (list(filter(lambda k: re.match(".*CRC", k), list1[line2]))):
                            interface_CRC = list1[line2][1]
                    dict_list.append(
                        named_tuple(interface_name, interface_input, interface_output, interface_CRC))
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_portchannels(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWPORTCHANNEL, CISCO_CLI_TERMINAL)
            dict_list = []
            named_tuple = namedtuple('PortChannels', ['EtherChannel', 'Mode', 'Ports'])
            for index, line in enumerate(list1[:-1]):
                if ([k for k in line if re.match("Po.*\(.*\)", k)] and len(line) > 2):
                    interfaces = line[3:].copy()
                    for line2 in range(index + 1, len(list1) - 1):
                        if ([k for k in list1[line2] if re.match("Po.*\(.*\)", k)] and len(line) > 2):
                            break
                        else:
                            interfaces += list1[line2]
                    dict_list.append(named_tuple(line[1], line[2], interfaces))
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_arp(ssh_client=None, vrf_name=""):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWARP + " " + vrf_name + "\n", CISCO_CLI_TERMINAL)
            named_tuple = namedtuple('ARP', ['IPAddress', 'Age', 'MAC', 'Vlan'])
            dict_list = [named_tuple(m[1], m[2], m[3], m[-1]) for m in list1 if len(m) > 3 if "ARPA" in m[-2]]
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_ip_interfaces(ssh_client=None, vrf_name=""):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWIPINTERFACES.format(vrf_name), CISCO_CLI_TERMINAL,
                                           split_type="COMMA")
            named_tuple = namedtuple('IPInterface', ['Interface', 'IP'])
            dict_list = list()
            print(list1)
            for index, line in enumerate(list1[:-1]):
                if ([k for k in line if re.match("line.*protocol.*is", k)] and len(line) > 0):
                    interface_name = line[0].split(" ")[0]
                    interface_IP = ""
                    for line2 in range(index + 1, len(list1) - 1):
                        if ([k for k in list1[line2] if re.match("line.*protocol.*is", k)] and len(line) > 0):
                            break
                        elif ([k for k in list1[line2] if re.match("internet address.*", k.lower())]):
                            interface_IP = list1[line2][-1]
                            dict_list.append(named_tuple(interface_name, interface_IP))
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_routes(ssh_client=None, vrf_name=""):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWROUTE.format(vrf_name), CISCO_CLI_TERMINAL,
                                           split_type="COMMA")
            named_tuple = namedtuple('IPInterface', ['Interface', 'IP'])
            dict_list = list()
            print(list1)

        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_stp(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWSTP, CISCO_CLI_TERMINAL,
                                           split_type="COMMA")
            named_tuple = namedtuple('STP', ['Vlan', 'BridgeID', 'RootID', 'RootPort',
                                             'TCN', 'TCN_Interface'])
            dict_list = list()
            #print(list1)
            for index, line in enumerate(list1[:-1]):
                if ([k for k in line if re.match(".*compatible.*Spanning Tree protocol.*", k)]):
                    vlan_name = line[0].split(" ")[0]
                    local_bridge_id, root_bridge_id, root_port, topology_change_time, topology_change_port = "", "", "", "", ""
                    for line2 in range(index + 1, len(list1) - 1):
                        if ([k for k in list1[line2] if re.match(".*compatible.*Spanning Tree protocol.*", k)]):
                            break
                        elif ([k for k in list1[line2] if re.match(".*Bridge Identifier has priority.*", k)]):
                            local_bridge_id = list1[line2][0].split(" ")[-1] + "-" + list1[line2][-1].split(" ")[-1]
                        elif ([k for k in list1[line2] if re.match(".*Current root has priority.*", k)]):
                            root_bridge_id = list1[line2][0].split(" ")[-1] + "-" + list1[line2][-1].split(" ")[-1]
                        elif ([k for k in list1[line2] if re.match(".*Root port is.*", k)]):
                            root_port = list1[line2][0].split(" ")[-1].replace("(", "").replace(")", "")
                        elif ([k for k in list1[line2] if re.match(".*Number of topology changes.*", k)]):
                            topology_change_time = list1[line2][0].split(" ")[-2]
                            topology_change_port = list1[line2 + 1][0].split(" ")[-1]
                    if (root_port == ""):
                        root_port = "Root Bridge"
                    dict_list.append(
                        named_tuple(vlan_name, local_bridge_id, root_bridge_id, root_port, topology_change_time,
                                    topology_change_port))
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_trunks(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWTRUNK, CISCO_CLI_TERMINAL, split_type="2+SPACE")
            named_tuple = namedtuple('Trunk', ['Interface', 'Status', 'AllowedVlan'])
            dict_list = list()
            #print(list1)
            for index, line in enumerate(list1[:-1]):
                if ([k for k in line if "Encapsulation" == k] and len(line) > 1):
                    for line2 in range(index + 1, len(list1) - 1):
                        if ([k for k in list1[line2] if re.match(".*allowed on trunk", k)]):
                            break
                        if (len(list1[line2]) > 1):
                            trunk_interface = list1[line2][0]
                            trunk_status = list1[line2][-2]
                            trunk_allowed_vlans = ""
                            for line3 in range(index + 1, len(list1) - 1):
                                if ([k for k in list1[line3] if re.match(".*allowed on trunk", k)]):
                                    for line4 in range(line3 + 1, 10000):
                                        if (list1[line4][0] == trunk_interface):
                                            trunk_allowed_vlans = list1[line4][-1]
                                            break
                                    break
                            dict_list.append(named_tuple(trunk_interface, trunk_status, trunk_allowed_vlans))
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_uptime(ssh_client=None):
        if ssh_client:
            dict_list = []
            dict_control = []
            named_tuple = namedtuple("Uptime", ("Switch", "Time", "Model", "Version"))
            sys_uptime = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWVERSION, CISCO_CLI_TERMINAL,
                                                split_type="2+SPACE")
            for index, i in enumerate(sys_uptime):
                for i2 in i:
                    if ("SW Version" == i2):
                        for i3 in sys_uptime[index + 2:]:
                            if (not len(i3)):
                                break
                            sw = "Switch" + str(i3[-4].split(" ")[0])
                            sw_model = str(i3[-3])
                            sw_version = str(i3[-2])
                            dict_control.append({"SW": sw, "SWModel": sw_model, "SWVersion": sw_version})
            for index, i in enumerate(sys_uptime):
                for i2 in i:
                    if ("uptime is" in i2):
                        sw = "N/A"
                        for i3 in sys_uptime[index:]:
                            if ("*" in i3):
                                sw = "Switch" + str(i3[1].split(" ")[0])
                                break
                        day = 0
                        daylist = i2.split("uptime is")[-1].replace(": ", "").replace(" ", "").split(",")
                        for i3 in daylist:
                            if ("year" in i3): day += int(i3.replace("years", "").replace("year", "")) * 365
                            if ("week" in i3): day += int(i3.replace("weeks", "").replace("week", "")) * 7
                            if ("day" in i3):
                                day += int(i3.replace("days", "").replace("day", ""))
                            if ("hour" in i3):
                                day += round(int(i3.replace("hours", "").replace("hour", "")) / 24, 1)
                        try:
                            dict_match = [k for k in dict_control if k["SW"] == sw][0]
                            dict_list.append(named_tuple(sw, day, dict_match["SWModel"], dict_match["SWVersion"]))
                        except:
                            dict_list.append(named_tuple(sw, day, "N/A", "N/A"))
                    if ("switch uptime" in i2.lower()):
                        # print(sys_uptime[index-2][0].replace(" 0",""))
                        day = 0
                        daylist = i[-1].replace(": ", "").replace(" ", "").split(",")
                        for i3 in daylist:
                            if ("year" in i3): day += int(i3.replace("years", "").replace("year", "")) * 365
                            if ("week" in i3): day += int(i3.replace("weeks", "").replace("week", "")) * 7
                            if ("day" in i3):
                                day += int(i3.replace("days", "").replace("day", ""))
                            if ("hour" in i3):
                                day += round(int(i3.replace("hours", "").replace("hour", "")) / 24, 1)
                        try:
                            dict_match = \
                                [k for k in dict_control if k["SW"] == sys_uptime[index - 2][0].replace(" 0", "")][0]
                            dict_list.append(
                                named_tuple(sys_uptime[index - 2][0].replace(" 0", ""), day, dict_match["SWModel"],
                                            dict_match["SWVersion"]))
                        except:
                            dict_list.append(named_tuple(sys_uptime[index - 2][0].replace(" 0", ""), day, "N/A", "N/A"))
            # print(dict_list)
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_show_run(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWRUN, CISCO_CLI_TERMINAL, split_type="NOSPLIT",
                                           sleep=15)
            named_tuple = namedtuple('UnderInterfaceConfig', ('Interface', 'Commands'))
            dict_list_under_interface = list()
            dict_list_global = list()
            for index, i in enumerate(list1):
                dict_list_global.append(i)
                if (re.search("^interface", i.lower())):
                    commands = []
                    interface = i.split(" ")[-1]
                    for index2, i2 in enumerate(list1[index + 1:]):
                        if (i2.startswith(" ")):
                            commands.append(i2)
                        else:
                            break
                    dict_list_under_interface.append(named_tuple(interface, commands))
            # print(list1)
            return dict_list_under_interface, dict_list_global
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_crashfile(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWCRASH, CISCO_CLI_TERMINAL, split_type="2+SPACE",
                                           sleep=15)
            dict_list = list()
            named_tuple = namedtuple('CrashFile', ('filename', 'Date'))
            for i in list1:
                if (len(i) > 1):
                    for i2 in i:
                        if ("crashinfo" in i2):
                            dict_list.append(named_tuple(i[-1], i[-2].split("+")[0]))
                            break
            return dict_list
        else:
            print("Call get_ssh function first")

    @staticmethod
    def get_span(ssh_client=None):
        if ssh_client:
            list1 = ssh_functions.__sender(ssh_client, CISCO_CLI_SHOWSPAN, CISCO_CLI_TERMINAL, split_type="COLON",
                                           sleep=5)
            dict_list = list()
            named_tuple = namedtuple('SPAN', ('SourceVlans', 'SourcePorts', 'DestinationPorts'))
            #print(list1)
            src_vlan, src_port, dst_port = list(), list(), list()
            for index, i in enumerate(list1):
                if ([o for o in i if ("Source VLANs" in o)]):
                    dummy_l1 = list1[index + 1][-1].split(",")
                    for i2 in dummy_l1:
                        if ("-" in i2):
                            dummy_l2 = i2.split("-")
                            for i3 in range(int(dummy_l2[0]), int(dummy_l2[1]) + 1):
                                src_vlan.append(str(i3))
                        else:
                            src_vlan.append(str(i2))
                    print(src_vlan)
                if ([o for o in i if ("Source Ports" in o)]):
                    dummy_l1 = list1[index + 1][-1].split(",")
                    for i2 in dummy_l1:
                        if ("-" in i2):
                            dummy_l3 = i2.split("/")
                            dummy_l2 = [o.replace(r",\x08", "") for o in dummy_l3]
                            dummy_l2 = dummy_l2[-1].split("-")

                            print(dummy_l2)
                            for i3 in range(int(dummy_l2[0]), int(dummy_l2[1]) + 1):
                                src_port.append(dummy_l3[0] + "/" + dummy_l3[1] + "/" + str(i3))
                        else:
                            src_port.append(str(i2).replace(r",\x08", ""))
                    print(src_port)
                if ([o for o in i if ("Destination Ports" in o)]):
                    dummy_l1 = list1[index][-1].split(",")
                    for i2 in dummy_l1:
                        if ("-" in i2):
                            dummy_l3 = i2.split("/")
                            dummy_l2 = [o.replace(r",\x08", "") for o in dummy_l3]
                            print(dummy_l2)
                            dummy_l2 = dummy_l2[-1].split("-")

                            print(dummy_l2)
                            for i3 in range(int(dummy_l2[0]), int(dummy_l2[1]) + 1):
                                dst_port.append(dummy_l3[0] + "/" + dummy_l3[1] + "/" + str(i3))
                        else:
                            dst_port.append(str(i2).replace(r",\x08", ""))
                    print(dst_port)



        else:
            print("Call get_ssh function first")
