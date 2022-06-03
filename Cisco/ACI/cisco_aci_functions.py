from Network.network import Network
import requests, json, sys
from Network.Constants_ACI import *
from collections import namedtuple
from datetime import datetime, timedelta

class Ranger:
    def __init__(self, str1):
        self.alllist = []
        list1 = str1.split("-")
        firstRange_module = list1[0].split("/")[0].replace("eth", "")
        firstRange_port = list1[0].split("/")[1]
        secondRange_module = list1[1].split("/")[0].replace("eth", "")
        secondRange_port = list1[1].split("/")[1]
        if (int(firstRange_module) == int(secondRange_module)):
            for i in range(int(secondRange_port) - int(firstRange_port) + 1):
                self.alllist.append("eth" + str(firstRange_module) + "/" + str(int(firstRange_port) + i))
        else:
            for i in range(48 - int(firstRange_port) + 1):
                self.alllist.append("eth" + str(firstRange_module) + "/" + str(int(firstRange_port) + i))
            for i in range(int(secondRange_module) - int(firstRange_module)):
                if (i == int(secondRange_module) - int(firstRange_module) - 1):
                    for i2 in range(int(secondRange_port)):
                        self.alllist.append("eth" + secondRange_module + "/" + str(i2 + 1))
                else:
                    for i2 in range(48):
                        self.alllist.append("eth" + str(int(firstRange_module) + i + 1) + "/" + str(i2 + 1))


class my_dict(dict):
    def __init__(self, dict1):
        self.new_dict = dict()
        for key, value in dict1.items():
            if isinstance(value, dict):
                self.new_dict[key] = my_dict(value)
            else:
                self.new_dict[key] = value
        super().__init__(self.new_dict)

    def __missing__(self, key):
        return []


def list_to_dictionary(convert_list):
    converted_dict = {k2: k3 for k in convert_list for k2, k3 in k.items()}
    return converted_dict


class cisco_aci_functions:
    @staticmethod
    def audit(data):
        dummy_list = list()
        print(data[0])
        for audit in data:
            config_id=audit["aaaModLR"]["attributes"]["id"]
            change_time=audit["aaaModLR"]["attributes"]["created"]
            change_unixtime = (datetime.strptime("%s" % (change_time.split(".")[0]),
                                                     '%Y-%m-%dT%H:%M:%S')).timestamp()
            user=audit["aaaModLR"]["attributes"]["user"]
            object = audit["aaaModLR"]["attributes"]["affected"]
            change_type = audit["aaaModLR"]["attributes"]["ind"]
            dummy_list.append(audit_named_tuple(config_id,change_time,change_unixtime,user,object,change_type))
        return dummy_list
    @staticmethod
    def tenants(data):
        named_tuple = namedtuple("Tenant", ("TenantName"))
        dummy_list = list()
        for tenant in data:
            dummy_list.append(named_tuple(tenant["fvTenant"]["attributes"]["name"]))
        return dummy_list

    @staticmethod
    def pods(data):
        named_tuple = namedtuple("Pod", ("PodNumber"))
        dummy_list = list()
        for pod in data:
            dummy_list.append(named_tuple(pod["fabricPod"]["attributes"]["id"]))
        return dummy_list

    @staticmethod
    def vrfs(data, tenant, ref_list):
        for vrf in data:
            vrf_vzany_consumers, vrf_vzany_providers, vrf_preferred_group = list(), list(), ""
            vrf_dict = my_dict(vrf)
            vrf_name = vrf_dict["fvCtx"]["attributes"]["name"]
            vrf_policy_enforce = vrf_dict["fvCtx"]["attributes"]["pcEnfPref"]
            vrf_bd_enforce = vrf_dict["fvCtx"]["attributes"]["bdEnforcedEnable"]
            for i in vrf_dict["fvCtx"]["children"]:
                i = my_dict(i)
                if ("vzAny" in i):
                    vrf_preferred_group = i["vzAny"]["attributes"]["prefGrMemb"]
                    if (i["vzAny"]["children"]):
                        for i2 in i["vzAny"]["children"]:
                            if ("vzRsAnyToProv" in i2):
                                vrf_vzany_providers.append(i2["vzRsAnyToProv"]["attributes"]["tnVzBrCPName"])
                            if ("vzRsAnyToCons" in i2):
                                vrf_vzany_consumers.append(i2["vzRsAnyToCons"]["attributes"]["tnVzBrCPName"])
            ref_list.append(
                vrf_named_tuple(vrf_name, vrf_vzany_consumers, vrf_vzany_providers, vrf_preferred_group,
                                vrf_policy_enforce,
                                vrf_bd_enforce, tenant))

    @staticmethod
    def bridge_domains(data, tenant, ref_list):

        for bd in data:
            bd_l3_bindings, bd_subnets, bd_vrf, bd_vrf_tenant = list(), list(), "", ""
            bd_dict = my_dict(bd)
            bd_name = bd_dict["fvBD"]["attributes"]["name"]
            bd_arp_flooding = bd_dict["fvBD"]["attributes"]["arpFlood"]
            bd_ep_learning = bd_dict["fvBD"]["attributes"]["ipLearning"]
            bd_limit_ip_learning_to_subnet = bd_dict["fvBD"]["attributes"]["limitIpLearnToSubnets"]
            bd_l2_unknown_unicast = bd_dict["fvBD"]["attributes"]["unkMacUcastAct"]
            bd_l2_unknown_multicast = bd_dict["fvBD"]["attributes"]["unkMcastAct"]
            bd_unicast_routing = bd_dict["fvBD"]["attributes"]["unicastRoute"]
            bd_ep_move_detection = bd_dict["fvBD"]["attributes"]["epMoveDetectMode"]
            for i in bd_dict["fvBD"]["children"]:
                i = my_dict(i)
                if ("fvRsBDToNdP" in i):
                    bd_l3_bindings.append(i["fvRsBDToNdP"]["attributes"]["tRn"])
                if ("fvRsCtx" in i):
                    bd_vrf = i["fvRsCtx"]["attributes"]["tRn"].replace("ctx-", "")
                    bd_vrf_tenant = i["fvRsCtx"]["attributes"]["tDn"].split("/")[1].replace("tn-", "")
                if ("fvSubnet" in i):
                    bd_subnets.append(i["fvSubnet"]["attributes"]["ip"])
            ref_list.append(bd_named_tuple(bd_name, bd_arp_flooding, bd_ep_learning, bd_limit_ip_learning_to_subnet,
                                           bd_l2_unknown_unicast, bd_l2_unknown_multicast, bd_unicast_routing,
                                           bd_ep_move_detection, bd_vrf, bd_vrf_tenant, bd_subnets, bd_l3_bindings,
                                           tenant))

    @staticmethod
    def epgs(data, tenant, ref_list):
        for ap in data:
            ap = my_dict(ap)
            if ('fvAp' in ap):
                static_bindings_counter, domain_counter, contract_consumer_counter, contract_provider_counter = 0, 0, 0, 0
                uEPG_MAC_counter, uEPG_IP_counter = 0, 0
                ap_name = ap['fvAp']['attributes']['name']
                for epg in ap["fvAp"]["children"]:
                    epg = my_dict(epg)
                    if ("fvAEPg" in epg):
                        epg_static_bindings, epg_domain_bindings, epg_contract_consumer, epg_contract_provider = list(), list(), list(), list()
                        micro_epg_mac_condition, micro_epg_ip_condition = list(), list()
                        epg_name, epg_preferred_group, epg_intra_isolation, epg_bd_bindings_tenant, epg_bd_bindings, epg_flood_on_epg, epg_type = "", "", "", "", "", "", ""
                        epg_name = epg['fvAEPg']['attributes']['name']
                        epg_preferred_group = epg['fvAEPg']['attributes']['prefGrMemb']
                        epg_intra_isolation = epg['fvAEPg']['attributes']['pcEnfPref']
                        epg_flood_on_epg = epg['fvAEPg']['attributes']['floodOnEncap']
                        epg_type = "Regular-Epg" if epg['fvAEPg']['attributes'][
                                                        'isAttrBasedEPg'] == "no" else "Micro-Epg"
                        for epg_child in epg['fvAEPg']['children']:
                            if ("fvRsPathAtt" in epg_child):
                                str1 = epg_child["fvRsPathAtt"]["attributes"]["tDn"]
                                list1 = str1.split("/")
                                nodes = [
                                    i.replace("paths-", "").replace("prot", "") for i in list1 if ("protpaths" in i or "paths" in i)]
                                static_bindings = namedtuple("StaticBindings", ("Switch", "Port", "Vlan"))
                                epg_static_bindings.append(
                                    static_bindings(nodes[0], str1[str1.find("[") + 1:str1.find("]")],
                                                    epg_child["fvRsPathAtt"]["attributes"]["encap"]))
                                static_bindings_counter += 1
                            if ("fvRsDomAtt" in epg_child):
                                #print(epg_name,epg_child["fvRsDomAtt"]["attributes"])
                                #if(epg_child["fvRsDomAtt"]["attributes"]["resImedcy"]!="pre-provision" and "VMware" in epg_child["fvRsDomAtt"]["attributes"]["tDn"]):
                                #    print(epg_name,"resolutionimmediacy")
                                #if(epg_child["fvRsDomAtt"]["attributes"]["instrImedcy"]!="immediate" and "VMware" in epg_child["fvRsDomAtt"]["attributes"]["tDn"]):
                                #    print(epg_name,"deploymentimmediacy")
                                epg_domain_bindings.append(
                                    {"Domain":epg_child["fvRsDomAtt"]["attributes"]["tDn"].replace("uni/", "").replace(
                                        "vmmp-VMware/dom-", "").replace("phys-", ""),"Resolution":epg_child["fvRsDomAtt"]["attributes"]["resImedcy"],
                                     "Deployment":epg_child["fvRsDomAtt"]["attributes"]["instrImedcy"]})
                                domain_counter += 1
                            if ("fvRsBd" in epg_child):
                                epg_child = my_dict(epg_child)
                                epg_bd_bindings = epg_child["fvRsBd"]["attributes"]["tnFvBDName"]
                                epg_bd_bindings_tenant = epg_child["fvRsBd"]["attributes"]["tDn"].split("/")[1].replace(
                                    "tn-", "")
                            if ("fvRsCons" in epg_child):
                                consumer_bindings = namedtuple("ConsumerContract", ("contract_name", "contract_tenant"))
                                epg_contract_consumer.append(
                                    consumer_bindings(epg_child["fvRsCons"]["attributes"]["tnVzBrCPName"],
                                                      epg_child["fvRsCons"]["attributes"]["tDn"].split("/")[1].replace(
                                                          "tn-", "")))
                                contract_consumer_counter += 1
                            if ("fvRsProv" in epg_child):
                                provider_bindings = namedtuple("ProviderContract", ("contract_name", "contract_tenant"))
                                epg_contract_provider.append(
                                    provider_bindings(epg_child["fvRsProv"]["attributes"]["tnVzBrCPName"],
                                                      epg_child["fvRsProv"]["attributes"]["tDn"].split("/")[1].replace(
                                                          "tn-", "")))
                                contract_provider_counter += 1
                            if ("fvCrtrn" in epg_child):
                                if ("children" in epg_child["fvCrtrn"]):
                                    for micro_epg in epg_child['fvCrtrn']['children']:
                                        if ("fvMacAttr" in micro_epg):
                                            micro_epg_mac_condition.append(micro_epg["fvMacAttr"]["attributes"]["mac"])
                                            uEPG_MAC_counter += 1
                                        if ("fvIpAttr" in micro_epg):
                                            micro_epg_ip_condition.append(micro_epg["fvIpAttr"]["attributes"]["ip"])
                                            uEPG_IP_counter += 1
                        ref_list.append(
                            epg_named_tuple(ap_name, epg_name, micro_epg_ip_condition, micro_epg_mac_condition,
                                            epg_preferred_group,
                                            epg_intra_isolation, epg_static_bindings, epg_domain_bindings,
                                            epg_bd_bindings,
                                            epg_bd_bindings_tenant, epg_contract_consumer, epg_contract_provider,
                                            epg_flood_on_epg,
                                            epg_type, tenant))
                    elif (epg == ap["fvAp"]["children"][-1]):
                        ref_list.append(
                            epg_named_tuple(ap_name, epg_name, micro_epg_ip_condition, micro_epg_mac_condition,
                                            epg_preferred_group,
                                            epg_intra_isolation, epg_static_bindings, epg_domain_bindings,
                                            epg_bd_bindings,
                                            epg_bd_bindings_tenant, epg_contract_consumer, epg_contract_provider,
                                            epg_flood_on_epg,
                                            epg_type, tenant))

    @staticmethod
    def nodes(data, pod_number, ref_list):
        for node in data:
            node = my_dict(node)
            node_name = node["fabricNode"]["attributes"]["name"]
            node_id = node["fabricNode"]["attributes"]["id"]
            node_role = node["fabricNode"]["attributes"]["role"]
            node_state = node["fabricNode"]["attributes"]["fabricSt"]
            node_model = node["fabricNode"]["attributes"]["model"]
            node_SN = node["fabricNode"]["attributes"]["serial"]
            node_pod_id = pod_number
            ref_list.append(node_named_tuple(node_name, node_id, node_role, node_state, node_pod_id,node_model,node_SN))

    @staticmethod
    def interfaces(data_l1, data_sys, data_ep, switch,ref_list):
        for interface in data_l1:
            interface = my_dict(interface)
            lldp_named_tuple = namedtuple("LLDP", ("lldp_neighbor_port_desc", "lldp_neighbor_port_id",
                                                   "lldp_neighbor_sys_desc", "lldp_neighbor_sys_id",
                                                   "lldp_neighbor_mgmt_ip"))
            # print(interface)
            port = interface["l1PhysIf"]["attributes"]["id"]
            admin_state = interface["l1PhysIf"]["attributes"]["adminSt"]
            port_type = interface["l1PhysIf"]["attributes"]["portT"]
            operational_state, last_link_state_change, sfp_SN, bundle = "", "", "N/A", "N/A"
            sfp_type="N/A"
            ep_ip_list, ep_mac_list = [], []
            lldp_neighbor, cdp_neighbor = [], []
            interface_domain, cdp_neighbor = [], []
            for interface2 in interface["l1PhysIf"]["children"]:
                interface2 = my_dict(interface2)
                # print(interface2)
                if ("ethpmPhysIf" in interface2):
                    operational_state = interface2["ethpmPhysIf"]["attributes"]["operSt"]
                    last_link_state_change = interface2["ethpmPhysIf"]["attributes"]["lastLinkStChg"]
                    bundle = interface2["ethpmPhysIf"]["attributes"]["bundleIndex"]
                    for interface3 in interface2["ethpmPhysIf"]["children"]:
                        interface3 = my_dict(interface3)
                        # print(interface3)
                        if ("ethpmFcot" in interface3):
                            sfp_SN = interface3["ethpmFcot"]["attributes"]["guiSN"]
                            sfp_type = interface3["ethpmFcot"]["attributes"]["typeName"]
                            sfp_name = interface3["ethpmFcot"]["attributes"]["guiName"]
                            #print(switch,port,sfp_name,sfp_type)
                    for ep in data_ep:
                        if ("epmIpEp" in ep):
                            if (ep["epmIpEp"]["attributes"]["ifId"] == port or ep["epmIpEp"]["attributes"][
                                "ifId"] == bundle):
                                ep_ip_list.append(ep["epmIpEp"]["attributes"]["addr"])
                        if ("epmMacEp" in ep):
                            if (ep["epmMacEp"]["attributes"]["ifId"] == port or ep["epmMacEp"]["attributes"][
                                "ifId"] == bundle):
                                ep_mac_list.append(ep["epmMacEp"]["attributes"]["addr"])
                    for lldp in data_sys:
                        lldp = my_dict(lldp)
                        if (lldp["lldpAdjEp"]):
                            _local_port = lldp["lldpAdjEp"]["attributes"]["dn"]
                            _local_port = _local_port[_local_port.find("[") + 1:_local_port.find("]")]
                            if (_local_port == port):
                                lldp_neighbor_port_desc = lldp["lldpAdjEp"]["attributes"]["portDesc"]
                                lldp_neighbor_port_id = lldp["lldpAdjEp"]["attributes"]["portIdV"]
                                lldp_neighbor_sys_desc = lldp["lldpAdjEp"]["attributes"]["sysDesc"]
                                lldp_neighbor_sys_id = lldp["lldpAdjEp"]["attributes"]["sysName"]
                                lldp_neighbor_mgmt_ip = lldp["lldpAdjEp"]["attributes"]["mgmtIp"]
                                lldp_neighbor.append(lldp_named_tuple(lldp_neighbor_port_desc, lldp_neighbor_port_id,
                                                                      lldp_neighbor_sys_desc, lldp_neighbor_sys_id,
                                                                      lldp_neighbor_mgmt_ip))
                if ("fvDomDef" in interface2):
                    interface_domain.append(
                        interface2["fvDomDef"]["attributes"]["domPKey"].replace("uni/phys-", "").replace("uni/l3dom-",
                                                                                                         "").replace(
                            "uni/l2dom-", "").replace("uni/vmmp-VMware/dom-", ""))
            #print(switch, port, admin_state, operational_state, last_link_state_change, sfp_SN, bundle, lldp_neighbor,
            #      ep_ip_list, ep_mac_list)
            ref_list.append(interface_named_tuple(switch, port, admin_state, operational_state, port_type,
                                                        interface_domain, lldp_neighbor, cdp_neighbor, ep_ip_list,
                                                        ep_mac_list, bundle, sfp_SN, sfp_type,last_link_state_change))

    @staticmethod
    def contract(data_contract, tenant, ref_list):
        for contract in data_contract:
            contract = my_dict(contract)
            subject_named_tuple = namedtuple("Subject", ("subject_name", "subject_2way", "subject_filter"))

            contract_name = contract["vzBrCP"]["attributes"]["name"]
            contract_scope = contract["vzBrCP"]["attributes"]["scope"]
            contract_subjects = []
            for subject in contract["vzBrCP"]["children"]:
                subject = my_dict(subject)
                if ("vzSubj" in subject):
                    subject_name = subject["vzSubj"]["attributes"]["name"]
                    subject_2way = subject["vzSubj"]["attributes"]["revFltPorts"]
                    subject_filter = []
                    for filter in subject["vzSubj"]["children"]:
                        filter = my_dict(filter)
                        if ("vzRsSubjFiltAtt" in filter):
                            if ("action" in filter["vzRsSubjFiltAtt"]["attributes"]):
                                subject_filter.append(
                                    {"Action": filter["vzRsSubjFiltAtt"]["attributes"]["action"],
                                     "ContractName": contract_name,
                                     "Subject": subject_name,
                                     "FilterName": filter["vzRsSubjFiltAtt"]["attributes"]["tnVzFilterName"],
                                     "FilterTenant": filter["vzRsSubjFiltAtt"]["attributes"]["tDn"].split("/")[
                                         1].replace(
                                         "tn-", "")})
                            else:
                                subject_filter.append(
                                    {"Action": "permit", "ContractName": contract_name,
                                     "Subject": subject_name,
                                     "FilterName": filter["vzRsSubjFiltAtt"]["attributes"]["tnVzFilterName"],
                                     "FilterTenant": filter["vzRsSubjFiltAtt"]["attributes"]["tDn"].split("/")[
                                         1].replace(
                                         "tn-", "")})
                    contract_subjects.append(subject_named_tuple(subject_name, subject_2way, subject_filter))
            ref_list.append(contract_named_tuple(contract_name, tenant, contract_scope, contract_subjects))

    @staticmethod
    def filters(data_filter, tenant, ref_list):
        for filter in data_filter:
            filter = my_dict(filter)
            print(filter)
            filter_named_tuple = namedtuple("Filter", ("filter_name", "filter_tenant", "filter_entries"))
            filter_entries_named_tuple = namedtuple("FilterEntries",
                                                    ("name", "protocol", "dest_port_start", "dest_port_end"))
            filter_entries = []
            if ("vzFilter" in filter):
                filter_name = filter["vzFilter"]["attributes"]["name"]
                for filter2 in filter["vzFilter"]["children"]:
                    if ("vzEntry" in filter2):
                        filter_entries.append(filter_entries_named_tuple(filter2["vzEntry"]["attributes"]["name"],
                                                                         filter2["vzEntry"]["attributes"]["prot"],
                                                                         filter2["vzEntry"]["attributes"]["dFromPort"],
                                                                         filter2["vzEntry"]["attributes"]["dToPort"]))
                ref_list.append(filter_named_tuple(filter_name, tenant, filter_entries))

    @staticmethod
    def l3out(data_l3out, tenant, ref_list):
        for l3out in data_l3out:
            l3out = my_dict(l3out)
            if ("l3extOut" in l3out):
                l3out_name = l3out["l3extOut"]["attributes"]["name"]
                l3out_tenant = tenant
                l3out_vrf, l3out_vrf_tenant = "", ""
                for _children in l3out["l3extOut"]["children"]:
                    _children = my_dict(_children)
                    if ("l3extRsEctx" in _children):
                        l3out_vrf = _children["l3extRsEctx"]["attributes"]["tnFvCtxName"]
                        l3out_vrf_tenant = _children["l3extRsEctx"]["attributes"]["tDn"].split("/")[1].replace("tn-",
                                                                                                               "")
                ref_list.append(l3_named_tuple(l3out_name, l3out_tenant, l3out_vrf, l3out_vrf_tenant))

    @staticmethod
    def interface_policy(data, ref_list):
        link_policy, cdp_policy, lldp_policy = [], [], []
        lacp_policy, mcp_policy, stp_policy = [], [], []
        storm_policy = []

        for data1 in data:
            data1 = my_dict(data1)

            if ("fabricHIfPol" in data1):
                policy_name = data1["fabricHIfPol"]["attributes"]["name"]
                speed = data1["fabricHIfPol"]["attributes"]["speed"]
                auto_negotiation = data1["fabricHIfPol"]["attributes"]["autoNeg"]
                link_policy.append({"policy_name": policy_name, "speed": speed, "negotiation": auto_negotiation})
            if ("cdpIfPol" in data1):
                policy_name = data1["cdpIfPol"]["attributes"]["name"]
                cdp = data1["cdpIfPol"]["attributes"]["adminSt"]
                cdp_policy.append({"policy_name": policy_name, "cdp": cdp})
            if ("lldpIfPol" in data1):
                policy_name = data1["lldpIfPol"]["attributes"]["name"]
                lldp = data1["lldpIfPol"]["attributes"]["adminTxSt"]
                lldp_policy.append({"policy_name": policy_name, "lldp": lldp})
            if ("lacpLagPol" in data1):
                policy_name = data1["lacpLagPol"]["attributes"]["name"]
                lacp_mode = data1["lacpLagPol"]["attributes"]["mode"]
                lacp_policy.append({"policy_name": policy_name, "lacp_mode": lacp_mode})
            if ("mcpIfPol" in data1):
                policy_name = data1["mcpIfPol"]["attributes"]["name"]
                mcp = data1["mcpIfPol"]["attributes"]["adminSt"]
                mcp_policy.append({"policy_name": policy_name, "mcp": mcp})
            if ("stpIfPol" in data1):
                policy_name = data1["stpIfPol"]["attributes"]["name"]
                stp_control = data1["stpIfPol"]["attributes"]["ctrl"]
                stp_policy.append({"policy_name": policy_name, "stp": stp_control})
            if ("stormctrlIfPol" in data1):
                policy_name = data1["stormctrlIfPol"]["attributes"]["name"]
                storm_policy.append({"policy_name": policy_name})
        ref_list.append(interface_policy(link_policy, cdp_policy, lldp_policy, lacp_policy,
                                         mcp_policy, stp_policy, storm_policy))

    @staticmethod
    def interface_policy_group_acc(data, ref_list):
        for polGrp_acc in data:
            polGrp_acc = my_dict(polGrp_acc)
            polGrp_name = polGrp_acc["infraAccPortGrp"]["attributes"]["name"]
            cdp, speed, lldp, stp, mcp, storm_control, aep = "", "", "", "", "", "", ""
            for polGrp_acc2 in polGrp_acc["infraAccPortGrp"]["children"]:
                if ("infraRsCdpIfPol" in polGrp_acc2):
                    cdp = polGrp_acc2["infraRsCdpIfPol"]["attributes"]["tnCdpIfPolName"]
                if ("infraRsHIfPol" in polGrp_acc2):
                    speed = polGrp_acc2["infraRsHIfPol"]["attributes"]["tnFabricHIfPolName"]
                if ("infraRsLldpIfPol" in polGrp_acc2):
                    lldp = polGrp_acc2["infraRsLldpIfPol"]["attributes"]["tnLldpIfPolName"]
                if ("infraRsStpIfPol" in polGrp_acc2):
                    stp = polGrp_acc2["infraRsStpIfPol"]["attributes"]["tnStpIfPolName"]
                if ("infraRsMcpIfPol" in polGrp_acc2):
                    mcp = polGrp_acc2["infraRsMcpIfPol"]["attributes"]["tnMcpIfPolName"]
                if ("infraRsStormctrlIfPol" in polGrp_acc2):
                    storm_control = polGrp_acc2["infraRsStormctrlIfPol"]["attributes"]["tnStormctrlIfPolName"]
                if ("infraRsAttEntP" in polGrp_acc2):
                    aep = polGrp_acc2["infraRsAttEntP"]["attributes"]["tDn"].replace("uni/infra/attentp-", "")
            ref_list.append(
                interface_policy_group_acc(polGrp_name, cdp, speed, lldp, stp, mcp, storm_control, aep))

    @staticmethod
    def interface_policy_group_pc(data, ref_list):
        for polGrp_pc in data:
            polGrp_pc = my_dict(polGrp_pc)
            polGrp_name = polGrp_pc["infraAccBndlGrp"]["attributes"]["name"]
            cdp, speed, lldp, stp, mcp, storm_control, aep = "", "", "", "", "", "", ""
            for polGrp_pc2 in polGrp_pc["infraAccBndlGrp"]["children"]:
                if ("infraRsCdpIfPol" in polGrp_pc2):
                    cdp = polGrp_pc2["infraRsCdpIfPol"]["attributes"]["tnCdpIfPolName"]
                if ("infraRsHIfPol" in polGrp_pc2):
                    speed = polGrp_pc2["infraRsHIfPol"]["attributes"]["tnFabricHIfPolName"]
                if ("infraRsLldpIfPol" in polGrp_pc2):
                    lldp = polGrp_pc2["infraRsLldpIfPol"]["attributes"]["tnLldpIfPolName"]
                if ("infraRsStpIfPol" in polGrp_pc2):
                    stp = polGrp_pc2["infraRsStpIfPol"]["attributes"]["tnStpIfPolName"]
                if ("infraRsMcpIfPol" in polGrp_pc2):
                    mcp = polGrp_pc2["infraRsMcpIfPol"]["attributes"]["tnMcpIfPolName"]
                if ("infraRsStormctrlIfPol" in polGrp_pc2):
                    storm_control = polGrp_pc2["infraRsStormctrlIfPol"]["attributes"]["tnStormctrlIfPolName"]
                if ("infraRsAttEntP" in polGrp_pc2):
                    aep = polGrp_pc2["infraRsAttEntP"]["attributes"]["tDn"].replace("uni/infra/attentp-", "")
            ref_list.append(interface_policy_group_pc(polGrp_name, cdp, speed, lldp, stp, mcp, storm_control, aep))

    @staticmethod
    def interface_profile(data, ref_list):
        for intProf in data:
            intProf = my_dict(intProf)
            #print(intProf)
            interface_profile_name = intProf["infraAccPortP"]["attributes"]["name"]
            for intProf2 in intProf["infraAccPortP"]["children"]:
                if ("infraHPortS" in intProf2):
                    intselect_name = intProf2["infraHPortS"]["attributes"]["name"]
                    intselect_port = []
                    polgrp_type, policy_group = "", ""
                    for m3 in intProf2["infraHPortS"]["children"]:
                        if ("infraPortBlk" in m3):
                            start_module = m3["infraPortBlk"]["attributes"]["fromCard"]
                            start_port = m3["infraPortBlk"]["attributes"]["fromPort"]
                            end_module = m3["infraPortBlk"]["attributes"]["toCard"]
                            end_port = m3["infraPortBlk"]["attributes"]["toPort"]
                            if (start_module + "/" + start_port == end_module + "/" + end_port):
                                intselect_port.append("eth" + start_module + "/" + start_port)
                            else:
                                intselect_port.append(
                                    "eth" + start_module + "/" + start_port + "-" + "eth" + end_module + "/" + end_port)
                        if ("infraRsAccBaseGrp" in m3):
                            polgrp_type = "access" if (
                                    "accportgrp-" in m3["infraRsAccBaseGrp"]["attributes"]["tDn"]) else "bundle"
                            policy_group = (m3["infraRsAccBaseGrp"]["attributes"]["tDn"]).replace(
                                "uni/infra/funcprof/accportgrp-", "").replace(
                                "uni/infra/funcprof/accbundle-", "")
                    copy_IntSelectPort = intselect_port.copy()
                    for mm1 in intselect_port:
                        if ("-" in mm1):
                            a = Ranger(mm1)
                            copy_IntSelectPort.remove(mm1)
                            for mm2 in a.alllist:
                                copy_IntSelectPort.append(mm2)
                    intselect_port = copy_IntSelectPort.copy()
                    ref_list.append(
                        interface_profile_tuple(interface_profile_name, intselect_name, polgrp_type, policy_group,
                                                intselect_port))

    @staticmethod
    def switch_profile(data, ref_list):
        for sw_prof in data:
            sw_prof = my_dict(sw_prof)
            switch_profile_name = sw_prof["infraNodeP"]["attributes"]["name"]
            sw_prof_interface_profile = []
            sw_prof_nodes = []
            #print(sw_prof)
            for sw_prof2 in sw_prof["infraNodeP"]["children"]:
                if ("infraRsAccPortP" in sw_prof2):
                    sw_prof_interface_profile.append(
                        {"IntProfName": sw_prof2["infraRsAccPortP"]["attributes"]["tDn"].replace(
                            "uni/infra/accportprof-", ""), "State": sw_prof2["infraRsAccPortP"]["attributes"]["state"]})
                if ("infraLeafS" in sw_prof2):
                    for sw_prof3 in sw_prof2["infraLeafS"]["children"]:
                        if ("infraNodeBlk" in sw_prof3):
                            if ((sw_prof3["infraNodeBlk"]["attributes"]["from_"]) == (
                                    sw_prof3["infraNodeBlk"]["attributes"]["to_"])):
                                sw_prof_nodes.append(sw_prof3["infraNodeBlk"]["attributes"]["from_"])
                            else:
                                init_sw=int(sw_prof3["infraNodeBlk"]["attributes"]["from_"])
                                end_sw=int(sw_prof3["infraNodeBlk"]["attributes"]["to_"])
                                for o in range(init_sw,end_sw+1):
                                    sw_prof_nodes.append(str(o))

            ref_list.append(switch_profile_tuple(switch_profile_name, sw_prof_interface_profile, sw_prof_nodes))

    @staticmethod
    def aep(data, ref_list):
        for aep in data:
            aep = my_dict(aep)
            aep_name = aep["infraAttEntityP"]["attributes"]["name"]
            aep_domains = []
            for aep2 in aep["infraAttEntityP"]["children"]:
                if ("infraRsDomP" in aep2):
                    aep_domains.append(
                        (aep2["infraRsDomP"]["attributes"]["tDn"]).replace("uni/phys-", "").replace("uni/l3dom-", "").
                            replace("uni/l2dom-", "").replace("uni/vmmp-VMware/dom-", ""))
                ref_list.append(aep_tuple(aep_name, aep_domains))

    @staticmethod
    def domain(data, ref_list):
        for domain in data:
            domain = my_dict(domain)
            domain_name = ""
            if ("physDomP" in domain):
                domain_name = domain["physDomP"]["attributes"]["name"]
            if ("l2extDomP" in domain):
                domain_name = domain["l2extDomP"]["attributes"]["name"]
            if ("l3extDomP" in domain):
                domain_name = domain["l3extDomP"]["attributes"]["name"]
            if ("compDom" in domain):
                domain_name = domain["compDom"]["attributes"]["name"]
            ref_list.append(domain_tuple(domain_name))

    @staticmethod
    def vlan_pool(data, ref_list):
        for vlan_pool in data:
            vlan_pool = my_dict(vlan_pool)
            vlan_pool_name = vlan_pool["fvnsVlanInstP"]["attributes"]["name"]
            vlan_pool_encap = []
            vlan_pool_domains = []
            for vlan_pool2 in vlan_pool["fvnsVlanInstP"]["children"]:
                if ("fvnsEncapBlk" in vlan_pool2):
                    encap_from = vlan_pool2["fvnsEncapBlk"]["attributes"]["from"]
                    encap_to = vlan_pool2["fvnsEncapBlk"]["attributes"]["to"]
                    if (encap_from == encap_to):
                        vlan_pool_encap.append(encap_to.replace("vlan-", ""))
                    else:
                        vlan_pool_encap.append(encap_from.replace("vlan-", "") + "-" + encap_to.replace("vlan-", ""))
                if ("fvnsRtVlanNs" in vlan_pool2):
                    vlan_pool_domains.append(vlan_pool2["fvnsRtVlanNs"]["attributes"]["tDn"].replace("uni/phys-", "").
                        replace("uni/l3dom-", "").replace("uni/l2dom-", "").replace(
                        "uni/vmmp-VMware/dom-", ""))
            ref_list.append(vlan_pool_tuple(vlan_pool_name, vlan_pool_domains, vlan_pool_encap))

    @staticmethod
    def endpoints(data, tenant, ap, epg, ref_list):
        if (len(data) > 0):
            for ep in data:
                ep = my_dict(ep)
                if ("fvCEp" in ep):
                    ep_mac = ep["fvCEp"]["attributes"]["mac"]
                    ep_ip = []
                    ep_switch, ep_interface = "", ""
                    for ep2 in ep["fvCEp"]["children"]:
                        if ("fvRsCEpToPathEp" in ep2):
                            if ("learned" in ep2["fvRsCEpToPathEp"]["attributes"]["lcC"]):
                                dummy1 = ep2["fvRsCEpToPathEp"]["attributes"]["tDn"].split("paths-")[1]
                                dummylist = dummy1.split("/pathep-")
                                ep_switch = dummylist[0]
                                ep_interface = dummylist[1].replace("[", "").replace("]", "")
                        if ("fvIp" in ep2):
                            ep_ip.append(ep2["fvIp"]["attributes"]["addr"])
                    ref_list.append(endpoint_tuple(ep_mac, ep_ip, ep_switch, ep_interface, tenant, ap, epg))
        else:
            ep_mac, ep_ip, ep_switch, ep_interface = "", [], "", ""
            ref_list.append(endpoint_tuple(ep_mac, ep_ip, ep_switch, ep_interface, tenant, ap, epg))

    @staticmethod
    def single_endpoints(data, ref_list):
        print(data)
        for i in data:
            if ("fvCEp" in i):
                list1 = i["fvCEp"]["attributes"]["dn"].split("/")
                dummy = {"epg": "", "tenant": "", "ap": ""}
                for i2 in list1:
                    if ("epg-" in i2):
                        dummy["epg"] = i2.replace("epg-", "")
                    if ("tn-" in i2):
                        dummy["tenant"] = i2.replace("tn-", "")
                    if ("ap-" in i2):
                        dummy["ap"] = i2.replace("ap-", "")
                ref_list.append(dummy)
