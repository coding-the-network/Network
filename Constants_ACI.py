from collections import namedtuple

ACI_AUTHENTICATION_URL = "https://%s/api/aaaLogin.json"
ACI_AUTHENTICATION_DATA = "{\"aaaUser\":{\"attributes\":{\"name\":\"%s\" , \"pwd\":\"%s\"}}}"

ACI_TENANT_URL = "https://%s/api/node/class/fvTenant.json"

# VRF related constants
ACI_VRF_URL = "https://%s/api/node/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=fvCtx&rsp-subtree=full&rsp-subtree-class=vzAny"
vrf_named_tuple = namedtuple("Vrf", ("vrf_name", "vrf_vzany_consumers", "vrf_vzany_providers",
                                     "vrf_preferred_group", "vrf_policy_enforce", "vrf_bd_enforce",
                                     "tenant"))

# BD related constants
ACI_BD_URL = "https://%s/api/node/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=fvBD&rsp-subtree=full&rsp-subtree-class=fvSubnet,fvRsCtx,fvRsBDToNdP"
bd_named_tuple = namedtuple("BD",
                            ("bd_name", "bd_arp_flooding", "bd_ep_learning", "bd_limit_ip_learning_to_subnet",
                             "bd_l2_unknown_unicast", "bd_l2_unknown_multicast", "bd_unicast_routing",
                             "bd_ep_move_detection", "bd_vrf", "bd_vrf_tenant", "bd_subnets", "bd_l3_bindings",
                             "tenant"))

# EPG related constants

ACI_EPG_EP_URL = 'https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json?query-target=children&target-subtree-class=fvCEp&rsp-subtree=children&rsp-subtree-class=fvRsToVm,fvRsVm,fvRsHyper,fvRsCEpToPathEp,fvIp,fvPrimaryEncap'
ACI_EPG_URL = "https://%s/api/node/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=fvAp&rsp-subtree=full&rsp-subtree-class=fvAEPg,fvRsBd,fvRsPathAtt,fvRsDomAtt,fvRsCons,fvRsProv,fvCrtrn"
epg_named_tuple = namedtuple("EPG",
                             ("ap_name", "epg_name", "micro_epg_ip_condition", "micro_epg_mac_condition",
                              "epg_preferred_group", "epg_intra_isolation", "epg_static_bindings",
                              "epg_domain_bindings", "epg_bd_bindings", "epg_bd_bindings_tenant",
                              "epg_contract_consumer", "epg_contract_provider", "epg_flood_on_epg",
                              "epg_type", "tenant"))

# Interface related constants
ACI_POD_URL = "https://%s/api/node/class/fabricPod.json"
ACI_NODES_URL = "https://%s/api/node/mo/topology/pod-%s.json?query-target=subtree&target-subtree-class=fabricNode"
ACI_INTERFACE_L1_URL = "https://%s/api/node/class/topology/pod-%s/node-%s/l1PhysIf.json?rsp-subtree=full&rsp-subtree-class=fvDomDef,ethpmPhysIf"
ACI_INTERFACE_SYS_URL = "https://%s/api/node/mo/topology/pod-%s/node-%s/sys.json?query-target=subtree&target-subtree-class=lldpAdjEp,cdpAdjEp,pcAggrIf"
ACI_INTERFACE_EP_URL = 'https://%s/api/node/mo/topology/pod-%s/node-%s/sys.json?query-target=subtree&target-subtree-class=epmMacEp,epmIpEp&query-target-filter=or(eq(epmMacEp.flags,"ip,local,mac"),eq(epmIpEp.flags,"local"),eq(epmMacEp.flags,"local,mac,vpc-attached"),eq(epmIpEp.flags,"local,vpc-attached"))'

node_named_tuple = namedtuple("Node", ("node_name", "node_id", "node_role", "node_state", "node_pod_id","node_model","node_SN"))

interface_named_tuple = namedtuple("Interface", (
    "switch", "port", "admin_state", "operational_state", "type", "domain", "lldp_neighbor", "cdp_neighbor",
    "EP_IPs", "EP_MACs", "bundle", "sfp_SN","sfp_type" ,"last_link_state_change"))

# Contract related constants

ACI_FILTER_URL = "https://%s/api/node/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=vzFilter&rsp-subtree=full"
ACI_CONTRACT_URL = "https://%s/api/node/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=vzBrCP&rsp-subtree=full"

contract_named_tuple = namedtuple("Contract", (
    "contract_name", "contract_tenant", "contract_scope", "contract_subjects"))

filter_named_tuple = namedtuple("Filter", ("filter_name", "filter_tenant", "filter_entries"))


ACI_L3OUT_URL="https://%s/api/node/mo/uni/tn-%s.json?query-target=subtree&target-subtree-class=l3extOut&rsp-subtree=full"
l3_named_tuple = namedtuple("l3out", ("l3out_name", "l3out_tenant", "l3out_vrf", "l3out_vrf_tenant"))
# Policy related constants

ACI_INTERFACE_POLICY_URL = "https://%s/api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class=fabricHIfPol,cdpIfPol,lldpIfPol,lacpLagPol,mcpIfPol,stpIfPol,stormctrlIfPol"
ACI_INTERFACE_POLICY_GROUP_ACC_URL = "https://%s/api/node/mo/uni/infra/funcprof.json?query-target=subtree&target-subtree-class=infraAccPortGrp&rsp-subtree=full&rsp-subtree-class=infraRsCdpIfPol,infraRsHIfPol,infraRsLldpIfPol,infraRsStpIfPol,infraRsMcpIfPol,infraRsStormctrlIfPol,infraRsAttEntP"
ACI_INTERFACE_POLICY_GROUP_PC_URL = "https://%s/api/node/mo/uni/infra/funcprof.json?query-target=subtree&target-subtree-class=infraAccBndlGrp&rsp-subtree=full&rsp-subtree-class=infraRsCdpIfPol,infraRsMcpIfPol,infraRsHIfPol,infraRsLldpIfPol,infraRsLacpPol,infraRsStpIfPol,infraRsAttEntP,infraRsStormctrlIfPol"
ACI_SWITCH_PROFILE_URL = "https://%s/api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class=infraNodeP&rsp-subtree=full&rsp-subtree-class=infraLeafS,infraNodeBlk,infraRsAccNodePGrp,infraRsAccPortP,infraRsAccCardP"
ACI_INTERFACE_PROFILE_URL = "https://%s/api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class=infraAccPortP&rsp-subtree=full&rsp-subtree-class=infraFexP,infraHPortS,infraPortBlk,infraSubPortBlk,infraRsAccBaseGrp"
ACI_AEP_URL = "https://%s/api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class=infraAttEntityP&rsp-subtree=full&rsp-subtree-class=infraRsDomP"
ACI_DOMAIN_URL = "https://%s/api/node/mo/uni.json?query-target=subtree&target-subtree-class=physDomP,l2extDomP,l3extDomP"
ACI_DOMAIN_VMM_URL = "https://%s/api/node/mo/comp/prov-VMware.json?query-target=children&target-subtree-class=compDom"
ACI_VLAN_POOL_URL = "https://%s/api/node/mo/uni/infra.json?query-target=subtree&target-subtree-class=fvnsVlanInstP&rsp-subtree=full&rsp-subtree-class=tagAliasInst,fvnsEncapBlk,fvnsRtVlanNs"

####

interface_policy = namedtuple("InterfacePolicy",
                              ("link_policy", "cdp_policy", "lldp_policy", "lacp_policy", "mcp_policy",
                               "stp_policy", "storm_policy"))

####

interface_policy_group_acc = namedtuple("InterfacePolicyGroupAcc",
                                        ("polGrp_name", "cdp", "speed", "lldp", "stp", "mcp", "storm_control", "aep"))
####

interface_policy_group_pc = namedtuple("InterfacePolicyGroupPc",
                                       ("polGrp_name", "cdp", "speed", "lldp", "stp", "mcp", "storm_control", "aep"))
####
####
policy_named_tuple = namedtuple("Policy", (
    "switch_profile", "interface_profile", "interface_policy", "interface_polGrp_acc", "interface_polGrp_pc", "aep",
    "vlan_pool", "domain"))
####
####
interface_profile_tuple = namedtuple("InterfaceProfile",
                                     ("intprof_name", "intselector_name", "intselector_policy_type",
                                      "intselector_policy_group", "intselector_ports"))

####
####
switch_profile_tuple = namedtuple("SwitchProfile",
                                  ("swprof_name", "swprof_interface_profiles", "swprof_nodes"))

####
####
aep_tuple = namedtuple("AEP", ("aep_name", "aep_domains"))
domain_tuple = namedtuple("Domains", ("domain_name"))
vlan_pool_tuple = namedtuple("VlanPool", ("vlan_pool_name", "vlan_pool_domains", "vlan_pool_encapsulation"))

# Endpoint constants
ACI_ENDPOINT_URL = "https://%s/api/node/mo/uni/tn-%s/ap-%s/epg-%s.json?query-target=children&target-subtree-class=fvCEp&rsp-subtree=children&rsp-subtree-class=fvRsCEpToPathEp,fvIp"
endpoint_tuple = namedtuple("Endpoints", ("ep_mac", "ep_ip", "ep_switch", "ep_interface", "tenant", "ap", "epg"))

ACI_ENDPOINT_URL_SINGLE = 'https://%s/api/node/class/fvCEp.json?rsp-subtree=full&rsp-subtree-include=required&rsp-subtree-filter=eq(fvIp.addr,"%s")'

ACI_AUDIT_URL='https://%s/api/node/class/aaaModLR.json?query-target-filter=not(wcard(aaaModLR.dn,"__ui_"))&order-by=aaaModLR.created|desc&page=%s&page-size=100'
audit_named_tuple = namedtuple("Audit", ("ConfigID","Time", "TimeUnix", "User", "Object", "Change"))
