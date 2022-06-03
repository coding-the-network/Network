import time
from Network.Constants import *
import sys, datetime
from collections import namedtuple
from pysnmp.hlapi import nextCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, \
    ObjectIdentity, bulkCmd


class snmp_functions:
    @staticmethod
    def __snmp(ip, community, oid):
        snmp = []
        for (errorIndication, errorStatus, errorIndex, varBinds) in bulkCmd(SnmpEngine(),
                                                                            CommunityData(community),
                                                                            UdpTransportTarget((ip, 161)),
                                                                            ContextData(), 0, 50,
                                                                            ObjectType(ObjectIdentity(oid)),
                                                                            lexicographicMode=False,
                                                                            lookupMib=False):
            if errorIndication:
                print(errorIndication, file=sys.stderr)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                      file=sys.stderr)
                break
            else:
                snmp.append({"key": str(varBinds[0][0]).replace(" ", ""),
                             "value": str(varBinds[0][1]).replace(" ", "")})
        return snmp

    @staticmethod
    def get_hostname(ip, snmp_community):
        hostname = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_HOSTNAME)

        return hostname[0]["value"] if hostname else ""

    @staticmethod
    def get_stack_role(ip, snmp_community):
        role = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_STACKDUTY)
        stack_role = []
        for m in role:
            if (m.get("value", False) == "1"):
                stack_role.append({"key": "Switch" + m["key"].split(".")[-1][0], "value": "Master"})
            elif (m.get("value", False) == "2"):
                stack_role.append({"key": "Switch" + m["key"].split(".")[-1][0], "value": "Member"})
            elif (m.get("value", False) == "4"):
                stack_role.append({"key": "Switch" + m["key"].split(".")[-1][0], "value": "Standby"})

        return stack_role

    @staticmethod
    def get_stack_status(ip, snmp_community):
        role = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_STACKSTATUS)
        stack_role = []
        for m in role:
            if (m.get("value", False) == "4"):
                stack_role.append({"key": "Switch" + m["key"].split(".")[-1][0], "value": "Ready"})
            elif (m.get("value", False) == "6"):
                stack_role.append({"key": "Switch" + m["key"].split(".")[-1][0], "value": "VersionMismatch"})
            elif (m.get("value", False) == "9"):
                stack_role.append({"key": "Switch" + m["key"].split(".")[-1][0], "value": "Provisioned"})
            elif (m.get("value", False) == "11"):
                stack_role.append({"key": "Switch" + m["key"].split(".")[-1][0], "value": "Removed"})

        return stack_role

    @staticmethod
    def get_POE(ip, snmp_community):
        role = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_POE)
        stack_role = []
        for m in role:
            key_split = m["key"].split(".")
            if (m.get("value", False) == "1"):
                stack_role.append({"key": "Switch" + key_split[-2] + "-Port" + key_split[-1], "value": "Disabled"})
            elif (m.get("value", False) == "2"):
                stack_role.append({"key": "Switch" + key_split[-2] + "-Port" + key_split[-1], "value": "OFF"})
            elif (m.get("value", False) == "3"):
                stack_role.append({"key": "Switch" + key_split[-2] + "-Port" + key_split[-1], "value": "ON"})

        return stack_role

    @staticmethod
    def get_interface_info(ip, snmp_community,sysuptime):
        named_tuple = namedtuple("Interface", ("Index", "Port", "Admin", "Operational",
                                               "Speed", "Description", "InputBytes", "OutputBytes",
                                               "CRC", "LastStateChange"))
        index_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_PORTINDEX)
        port_name_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_PORTNAME)
        port_admin_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_ADMINSTATUS)
        port_oper_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_OPERATIONALSTATUS)
        port_speed_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_PORTSPEED)
        port_desc_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_DESCRIPTION)
        port_unicastinput_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_INPUTUNICASTPACKET)
        port_unicastoutput_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_OUTPUTUNICASTPACKET)
        port_CRC_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CRC)
        port_lastlinkchange_list = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_LINKCHANGE)
        index_name_list = []
        # print(len(port_unicastinput_list), len(port_unicastoutput_list), len(port_CRC_list))
        for index, name, admin, oper, speed, desc in zip(index_list, port_name_list, port_admin_list,
                                                         port_oper_list, port_speed_list, port_desc_list):
            admin_status = "UP" if admin.get("value") == "1" else "DOWN"
            operational_status = "UP" if oper.get("value") == "1" else "DOWN"
            port_speed = speed.get("value") + "Mbps" if (
                    int(speed.get("value")) < 1000) else str(int(speed.get("value")) / 1000) + "Gbps"
            port_desc = desc.get("value")
            unicast_input, unicast_output, crc_interface, statechange_interface = "", "", "", ""
            for in_, out_ in zip(port_unicastinput_list, port_unicastoutput_list):
                in_port = in_.get("key").split(".")[-1]
                out_port = out_.get("key").split(".")[-1]
                # print(in_port, out_port, index.get("value"))
                if (in_port == index.get("value") and out_port == index.get("value")):
                    unicast_input = in_.get("value")
                    unicast_output = out_.get("value")
                    break
            for crc_ in port_CRC_list:
                crc_port = crc_.get("key").split(".")[-1]
                if (crc_port == index.get("value")):
                    crc_interface = crc_.get("value")
                    break
            for i3 in port_lastlinkchange_list:
                i3_ = i3.get("key").split(".")[-1]
                if (i3_ == index.get("value")):
                    statechange_interface = int(int(i3.get("value"))/100)
                    statechange_interface=str(datetime.timedelta(seconds=int(int(sysuptime)-int(statechange_interface))))
                    break

            index_name_list.append(named_tuple(index.get("value"), name.get("value"),
                                               admin_status, operational_status, port_speed,
                                               port_desc, unicast_input, unicast_output,
                                               crc_interface, statechange_interface))

        return index_name_list

    @staticmethod
    def get_uptime(ip, snmp_community):
        named_tuple = namedtuple("Uptime", ("Time", "Seconds"))
        sys_uptime = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_SYSUP)
        #print("HI",sys_uptime)
        dict_list = [named_tuple(str(datetime.timedelta(seconds=int(m.get("value")))), m.get("value")) for m in
                     sys_uptime]
        #print(dict_list)
        return dict_list

    @staticmethod
    def get_temp(ip, snmp_community):
        named_tuple = namedtuple("Temperature", ("Name", "Value", "Threshold", "Status"))
        temp_name = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_TEMPNAME)
        temp_value = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_TEMPVALUE)
        temp_threshold = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_TEMPTHRESHOLD)
        dict_list = []
        for temp, value, threshold in zip(temp_name, temp_value, temp_threshold):
            temp_status = "OK" if (int(value.get("value")) / int(threshold.get("value"))) < 0.8 else "NOT OK"
            dict_list.append(named_tuple(temp.get("value"), value.get("value"),
                                         threshold.get("value"), temp_status))
        return dict_list

    @staticmethod
    def get_fan(ip, snmp_community):
        named_tuple = namedtuple("Fan", ("Name", "Status"))
        fan_name = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_FANNAME)
        fan_status = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_FANSTATUS)
        dict_list = []
        for fan, status in zip(fan_name, fan_status):
            fan_status = "OK" if (status.get("value") == "1") else "NOT OK"
            dict_list.append(named_tuple(fan.get("value"), fan_status))
        return dict_list

    @staticmethod
    def get_power(ip, snmp_community):
        named_tuple = namedtuple("Power", ("Name", "Status"))
        power_name = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_POWERNAME)
        power_status = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_POWERSTATUS)
        dict_list = []
        for power, status in zip(power_name, power_status):
            power_status = "OK" if (status.get("value") == "1") else "NOT OK"
            dict_list.append(named_tuple(power.get("value"), power_status))
        return dict_list

    @staticmethod
    def get_cpu(ip, snmp_community):
        named_tuple = namedtuple("CPU", ("Switch", "CPU_1min", "CPU_5min"))
        cpu_1min = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CPUTOTAL1MIN)
        cpu_5min = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CPUTOTAL5MIN)
        dict_list = []
        counter = 1
        for _1min, _5min in zip(cpu_1min, cpu_5min):
            dict_list.append(named_tuple("Switch" + str(counter), _1min.get("value"), _5min.get("value")))
            counter += 1
        return dict_list

    @staticmethod
    def get_memory(ip, snmp_community):
        named_tuple = namedtuple("Memory", ("Switch", "FreeMemory"))
        memory_free = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_MEMORYFREE)
        dict_list = []
        counter = 1
        for memory in memory_free:
            dict_list.append(named_tuple("Switch" + str(counter), memory.get("value")))
            counter += 1
        return dict_list

    @staticmethod
    def get_vss(ip, snmp_community):
        named_tuple = namedtuple("VSS", ("VSSSwitch", "VSSStatus", "VSLStatus", "VSLConfPorts"
                                         , "VSLOperPorts"))
        dict_list = []
        counter = 1
        vsl_lastchange = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_VSSVSLCHANGE)
        vss_status = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_VSSSTATUS)
        vss_vsl_status = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_VSSVSL)
        vss_vsl_configured = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_VSSCONFPORT)
        vss_vsl_operational = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_VSSOPERPORT)
        for vss, vsl, conf_port, oper_port, vsl_last in zip(vss_status, vss_vsl_status, vss_vsl_configured,
                                                            vss_vsl_operational, vsl_lastchange):
            status_vss = {"1": "Standalone", "2": "Active", "3": "Standby"}
            status_vsl = {"1": "UP", "2": "DOWN"}
            dict_list.append(named_tuple("Switch{}".format(str(counter)), status_vss.get(vss.get("value")),
                                         status_vsl.get(vsl.get("value")), conf_port.get("value"),
                                         oper_port.get("value")))
        return dict_list

    @staticmethod
    def get_cdp(ip, snmp_community):
        named_tuple = namedtuple("CDP", ("CDPName", "CDPIp", "CDPModel", "CDPRemotePort"
                                         , "CDPLocalPort"))
        dict_list = []
        counter = 1
        cdp_ip = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CDPIP)
        cdp_name = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CDPNAME)
        cdp_model = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CDPModel)
        cdp_remote_port = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CDPRemotePort)
        cdp_local_port = snmp_functions.__snmp(ip, snmp_community, CISCO_SNMP_CDPLocalPort)
        for name, model, remote_port, remote_ip in zip(cdp_name, cdp_model, cdp_remote_port,
                                                       cdp_ip):
            port_index = name.get("key").split(".")[-2]
            local_port = ""
            for i in cdp_local_port:
                if (i.get("key").split(".")[-1] == port_index):
                    local_port = i.get("value")
                    break
            dict_list.append(named_tuple(name.get("value"), "N/A", model.get("value")
                                         , remote_port.get("value"), local_port))
        return dict_list
