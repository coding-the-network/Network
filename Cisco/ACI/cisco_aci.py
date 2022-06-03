from Network.network import Network
import requests, json, sys
from Network.Cisco.ACI.cisco_aci_functions import cisco_aci_functions as aci_func
import threading
from collections import namedtuple
import re, time
from Network.Constants_ACI import *
from datetime import datetime, timedelta

def list_printer(list1):
    while True:
        print("Press 'E' to exit")
        for index, data in enumerate(list1):
            print(str(index + 1) + "-", data, end="\t")
            if ((index + 1) % 3 == 0):
                print("")
        user_input = input("\nPlease select the number you desired")
        if (re.match("[0-9]+", user_input)):
            if (len(list1) >= int(user_input)):
                return int(user_input)
            else:
                print("Please select make your selection again. Invalid input")
        else:
            print("Please select make your selection again. Invalid input")


class Cisco_ACI:
    class Rest_Api(Network):
        def __init__(self, ip: str, username: str, password: str):
            self.headers = {
                'content-type': "application/json",
                'cache-control': "no-cache"
            }
            self.apic_cookie = {}
            super().__init__(ip)
            self.Locker = threading.Lock()
            self.__get_rest__(username=username, password=password)
            self.tenant_list = None
            self.pod_list = None
            self.node_list = None
            self.thread_list = []
            self.__vrf_list, self.__bd_list, self.__epg_list = [], [], []
            self.__contract_list, self.__filter_list = [], []
            self.__node_list = []
            self.__interface_policy_list = []
            self.__endpoints_list = []
            self.__l3out_list = []
            self.__interface_list=[]
            self.__audit_list=[]
        def __get_data__(self, url: str):
            try:
                response = requests.get(url=url, cookies=self.apic_cookie, verify=False)
            except requests.exceptions.ConnectTimeout:
                print("IP is not reachable. You need to call __get_rest__ function "
                      "again to continue")
                return
            if (response.status_code == 200):
                return response.json().get("imdata", None)
            else:
                print("Something went wrong while calling {}".format(url))
                return

        def __get_rest__(self, username: str, password: str) -> None:
            print(ACI_AUTHENTICATION_URL % self.ip)
            print(ACI_AUTHENTICATION_DATA % (username, password))
            try:
                auth = requests.post(ACI_AUTHENTICATION_URL % self.ip,
                                     ACI_AUTHENTICATION_DATA % (username, password), self.headers,
                                     verify=False, timeout=5)
            except requests.exceptions.ConnectTimeout:
                print("IP is not reachable. You need to call __get_rest__ function "
                      "again to continue")
                sys.exit()
            response_conditions = {200: "Authentication Succesfull",
                                   401: "Authentication Failure"}

            if (auth.status_code == 200):
                print("Authentication Succesfull to {}".format(self.ip))
                auth_token = auth.json()['imdata'][0]['aaaLogin']['attributes']['token']
                self.apic_cookie['APIC-Cookie'] = auth_token
            else:
                print(response_conditions.get(auth.status_code, "Something went wrong"))
                sys.exit()

        def __calling(self, function, url, *args):
            print("Calling")
            data = self.__get_data__(url=url)
            assert data is not None
            with self.Locker:
                function(data, *args)

        def __threading(self, function, url, *args):
            print("Threading")
            x = threading.Thread(target=self.__calling, args=(function, url, *args))
            x.start()
            self.thread_list.append(x)
            if (threading.active_count() > 15):
                time.sleep(1)
        def audit(self,days=2):
            if self.apic_cookie:
                self.__audit_list.append(audit_named_tuple("dummy","dummy","dummy","dummy","dummy","dummy"))
                for repeat in range(20):
                    newlist=list()
                    audit_data = self.__get_data__(url=ACI_AUDIT_URL % (self.ip,str(repeat)))
                    assert audit_data is not None
                    newlist=aci_func.audit(audit_data)
                    self.__audit_list+=newlist
                    if((datetime.today()).timestamp()-newlist[-1].TimeUnix>3600*24*days):
                        break
                return self.__audit_list[1:]

            else:
                print("No apic-cookie")
        def tenants(self):
            """This function gets all tenants from APIC.

                This function gets name of the tenants. This function is used on other functions like epg and bd.If
            tenant info already retrieved from APIC, then it returns that value. Not getting new information
            from APIC.

            Returns
            -------
                namedtuples inside the list.
                [namedtuple("Tenant", ("TenantName"))]
            """
            if (self.tenant_list):
                return self.tenant_list
            if self.apic_cookie:
                tenant_data = self.__get_data__(url=ACI_TENANT_URL % self.ip)
                assert tenant_data is not None
                self.tenant_list = aci_func.tenants(tenant_data)
                return self.tenant_list

            else:
                print("No apic-cookie")

        def pods(self):
            """This function gets all pod IDs that is defined in this APIC.

                This function gets pod IDs and it is used for other functions like node function. If pod IDs already
            retrieved from APIC, then it returns that value. Not getting new information from APIC.

            Returns
            -------
                namedtuples inside the list.
                [namedtuple("Pod", ("PodNumber"))]
            """
            if (self.pod_list):
                return self.pod_list
            if self.apic_cookie:
                pod_data = self.__get_data__(url=ACI_POD_URL % self.ip)
                assert pod_data is not None
                self.pod_list = aci_func.pods(pod_data)
                return self.pod_list

            else:
                print("No apic-cookie")

        def L3out(self, tenant_selection: bool = False, _threading: bool = False, _refresh: bool = False):
            if (self.__l3out_list and not _refresh):
                return self.__l3out_list[1:]
            self.__l3out_list = []
            self.__l3out_list.append(l3_named_tuple("dummy", "dummy", "dummy", "dummy"))
            tenant_list = self.tenants()
            if tenant_selection:
                selection = list_printer(tenant_list)
                url = ACI_L3OUT_URL % (self.ip, tenant_list[selection - 1].TenantName)
                self.__calling(aci_func.l3out, url, tenant_list[selection - 1].TenantName, self.__l3out_list)
            else:
                for tenant in tenant_list:
                    url = ACI_L3OUT_URL % (self.ip, tenant.TenantName)
                    if (not _threading):
                        self.__calling(aci_func.l3out, url, tenant.TenantName, self.__l3out_list)
                    else:
                        self.__threading(aci_func.l3out, url, tenant.TenantName, self.__l3out_list)
                if (_threading):
                    thread_waiter(self.thread_list)
                    self.thread_list = []
            return self.__l3out_list[1:]

        def vrfs(self, tenant_selection: bool = False, _threading: bool = False, _refresh: bool = False):
            if (self.__vrf_list and not _refresh):
                return self.__vrf_list[1:]
            self.__vrf_list = []
            self.__vrf_list.append(vrf_named_tuple("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy"))
            tenant_list = self.tenants()
            if tenant_selection:
                selection = list_printer(tenant_list)
                url = ACI_VRF_URL % (self.ip, tenant_list[selection - 1].TenantName)
                self.__calling(aci_func.vrfs, url, tenant_list[selection - 1].TenantName, self.__vrf_list)
            else:
                for tenant in tenant_list:
                    url = ACI_VRF_URL % (self.ip, tenant.TenantName)
                    if (not _threading):
                        self.__calling(aci_func.vrfs, url, tenant.TenantName, self.__vrf_list)
                    else:
                        self.__threading(aci_func.vrfs, url, tenant.TenantName, self.__vrf_list)
                if (_threading):
                    thread_waiter(self.thread_list)
                    self.thread_list = []
            return self.__vrf_list[1:]

        def bridge_domains(self, tenant_selection: bool = False, _threading: bool = False, _refresh: bool = False):
            if (self.__bd_list and not _refresh):
                return self.__bd_list[1:]

            self.__bd_list = []
            self.__bd_list.append(bd_named_tuple("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy",
                                                 "dummy", "dummy", "dummy", "dummy", "dummy", "dummy"))
            tenant_list = self.tenants()
            if tenant_selection:
                selection = list_printer(tenant_list)
                url = ACI_BD_URL % (self.ip, tenant_list[selection - 1].TenantName)
                self.__calling(aci_func.bridge_domains, url, tenant_list[selection - 1].TenantName, self.__bd_list)
            else:
                for tenant in tenant_list:
                    url = ACI_BD_URL % (self.ip, tenant.TenantName)
                    if (not _threading):
                        self.__calling(aci_func.bridge_domains, url, tenant.TenantName, self.__bd_list)
                    else:
                        self.__threading(aci_func.bridge_domains, url, tenant.TenantName, self.__bd_list)
                if (_threading):
                    thread_waiter(self.thread_list)
                    self.thread_list = []
            return self.__bd_list[1:]

        def epgs(self, tenant_selection: bool = False, _threading: bool = False, _refresh: bool = False):
            if (self.__epg_list and not _refresh):
                return self.__epg_list[1:]
            self.__epg_list = []
            self.__epg_list.append(epg_named_tuple("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy",
                                                   "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy",
                                                   "dummy"))
            tenant_list = self.tenants()
            if tenant_selection:
                selection = list_printer(tenant_list)
                url = ACI_EPG_URL % (self.ip, tenant_list[selection - 1].TenantName)
                self.__calling(aci_func.epgs, url, tenant_list[selection - 1].TenantName, self.__epg_list)
            else:
                for tenant in tenant_list:
                    url = ACI_EPG_URL % (self.ip, tenant.TenantName)
                    if (not _threading):
                        self.__calling(aci_func.epgs, url, tenant.TenantName, self.__epg_list)
                    else:
                        self.__threading(aci_func.epgs, url, tenant.TenantName, self.__epg_list)
                if (_threading):
                    thread_waiter(self.thread_list)
                    self.thread_list = []
            return self.__epg_list[1:]

        def endpoints(self, tenant_selection: bool = False, epg_selection: bool = False, _threading: bool = True,
                      _refresh: bool = False, single_ep: str = ""):
            if (single_ep):
                self.__single_ep_epg = []
                url = ACI_ENDPOINT_URL_SINGLE % (self.ip, single_ep)
                self.__calling(aci_func.single_endpoints, url, self.__single_ep_epg)
                return self.__single_ep_epg
            if (self.__endpoints_list and not _refresh):
                return self.__endpoints_list[1:]
            self.__endpoints_list = []
            self.__endpoints_list.append(endpoint_tuple("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy"))
            tenant_list = self.tenants()
            epg_list = self.epgs(_threading=True)
            if tenant_selection:
                selection = list_printer(tenant_list)
                epg_list = [i for i in epg_list if i.tenant == tenant_list[selection - 1].TenantName]
                if epg_selection:
                    selection_epg = list_printer(epg_list)
                    url = ACI_ENDPOINT_URL % (
                        self.ip, tenant_list[selection - 1].TenantName, epg_list[selection_epg - 1].ap_name,
                        epg_list[selection_epg - 1].epg_name)

                    self.__calling(aci_func.endpoints, url, tenant_list[selection - 1].TenantName,
                                   epg_list[selection_epg - 1].ap_name,
                                   epg_list[selection_epg - 1].epg_name, self.__endpoints_list)
                else:
                    for epg in epg_list:
                        url = ACI_ENDPOINT_URL % (self.ip, epg.tenant, epg.ap_name, epg.epg_name)
                        if (not _threading):
                            self.__calling(aci_func.endpoints, url, epg.tenant, epg.ap_name, epg.epg_name,
                                           self.__endpoints_list)
                        else:
                            self.__threading(aci_func.endpoints, url, epg.tenant, epg.ap_name, epg.epg_name,
                                             self.__endpoints_list)
            else:
                for epg in epg_list:
                    url = ACI_ENDPOINT_URL % (self.ip, epg.tenant, epg.ap_name, epg.epg_name)
                    if (not _threading):
                        self.__calling(aci_func.endpoints, url, epg.tenant, epg.ap_name, epg.epg_name,
                                       self.__endpoints_list)
                    else:
                        self.__threading(aci_func.endpoints, url, epg.tenant, epg.ap_name, epg.epg_name,
                                         self.__endpoints_list)
            if (_threading):
                thread_waiter(self.thread_list)
                self.thread_list = []
            return self.__endpoints_list[1:]

        def contract(self, tenant_selection: bool = False, _threading: bool = False, _refresh: bool = False):
            if (self.__contract_list and not _refresh):
                return self.__contract_list[1:]
            self.__contract_list = []
            self.__contract_list.append(contract_named_tuple("dummy", "dummy", "dummy", "dummy"))
            tenant_list = self.tenants()
            if tenant_selection:
                selection = list_printer(tenant_list)
                url = ACI_CONTRACT_URL % (self.ip, tenant_list[selection - 1].TenantName)
                self.__calling(aci_func.contract, url, tenant_list[selection - 1].TenantName, self.__contract_list)
            else:
                for tenant in tenant_list:
                    url = ACI_CONTRACT_URL % (self.ip, tenant.TenantName)
                    if (not _threading):
                        self.__calling(aci_func.contract, url, tenant.TenantName, self.__contract_list)
                    else:
                        self.__threading(aci_func.contract, url, tenant.TenantName, self.__contract_list)
                if (_threading):
                    thread_waiter(self.thread_list)
                    self.thread_list = []
            return self.__contract_list[1:]

        def filter(self, tenant_selection: bool = False, _threading: bool = False, _refresh: bool = False):
            if (self.__filter_list and not _refresh):
                return self.__filter_list[1:]
            self.__filter_list = []
            self.__filter_list.append(filter_named_tuple("dummy", "dummy", "dummy"))
            tenant_list = self.tenants()
            if tenant_selection:
                selection = list_printer(tenant_list)
                url = ACI_FILTER_URL % (self.ip, tenant_list[selection - 1].TenantName)
                self.__calling(aci_func.filters, url, tenant_list[selection - 1].TenantName, self.__filter_list)
            else:
                for tenant in tenant_list:
                    url = ACI_FILTER_URL % (self.ip, tenant.TenantName)
                    if (not _threading):
                        self.__calling(aci_func.filters, url, tenant.TenantName, self.__filter_list)
                    else:
                        self.__threading(aci_func.filters, url, tenant.TenantName, self.__filter_list)
                    if (_threading):
                        thread_waiter(self.thread_list)
                        self.thread_list = []
            return self.__filter_list[1:]

        def nodes(self, pod_selection=False, _threading=False):
            self.__node_list = []
            self.__node_list.append(node_named_tuple("dummy", "dummy", "dummy", "dummy", "dummy","dummy","dummy"))
            pod_list = self.pods()
            if pod_selection:
                selection = list_printer(pod_list)
                url = ACI_NODES_URL % (self.ip, pod_list[selection - 1].PodNumber)
                self.__calling(aci_func.nodes, url, pod_list[selection - 1].PodNumber, self.__node_list)
            else:
                for pod in pod_list:
                    url = ACI_NODES_URL % (self.ip, pod.PodNumber)
                    if (not _threading):
                        self.__calling(aci_func.nodes, url, pod.PodNumber, self.__node_list)
                    else:
                        self.__threading(aci_func.nodes, url, pod.PodNumber,self.__node_list)
                if (_threading):
                    thread_waiter(self.thread_list)
                    self.thread_list = []
            return self.__node_list[1:]

        def interfaces(self, node_selection=False, _threading=False):
            def __threading_function(url1, url2, url3, node):
                print("Threading")
                interface_l1_data = self.__get_data__(url=url1)
                #print(interface_l1_data)
                interface_sys_data = self.__get_data__(url=url2)
                interface_ep_data = self.__get_data__(url=url3)
                assert interface_l1_data is not None
                assert interface_sys_data is not None
                assert interface_ep_data is not None
                with self.Locker:
                    aci_func.interfaces(interface_l1_data, interface_sys_data, interface_ep_data,
                                        node, self.__interface_list)
            self.__interface_list = []
            if self.apic_cookie:
                self.__interface_list.append(
                    interface_named_tuple("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy",
                                          "dummy",
                                          "dummy",
                                          "dummy", "dummy", "dummy", "dummy"))
                node_list = self.nodes()
                node_list = [(m.node_name, m.node_id, m.node_pod_id) for m in node_list if(m.node_state=="active")]
                if node_selection:
                    selection = list_printer(node_list)
                    interface_l1_data = self.__get_data__(
                        url=ACI_INTERFACE_L1_URL % (self.ip, node_list[selection - 1][2], node_list[selection - 1][1]))
                    assert interface_l1_data is not None
                    interface_sys_data = self.__get_data__(
                        url=ACI_INTERFACE_SYS_URL % (self.ip, node_list[selection - 1][2], node_list[selection - 1][1]))
                    assert interface_sys_data is not None
                    interface_ep_data = self.__get_data__(
                        url=ACI_INTERFACE_EP_URL % (self.ip, node_list[selection - 1][2], node_list[selection - 1][1]))
                    assert interface_ep_data is not None
                    aci_func.interfaces(interface_l1_data, interface_sys_data, interface_ep_data,
                                        node_list[selection - 1][0],self.__interface_list)
                    return self.__interface_list[1:]
                else:
                    if (not _threading):
                        for node in node_list:
                            interface_l1_data = self.__get_data__(
                                url=ACI_INTERFACE_L1_URL % (self.ip, node[2], node[1]))
                            assert interface_l1_data is not None
                            interface_sys_data = self.__get_data__(
                                url=ACI_INTERFACE_SYS_URL % (self.ip, node[2], node[1]))
                            assert interface_sys_data is not None
                            interface_ep_data = self.__get_data__(
                                url=ACI_INTERFACE_EP_URL % (self.ip, node[2], node[1]))
                            assert interface_ep_data is not None
                            aci_func.interfaces(interface_l1_data, interface_sys_data, interface_ep_data,
                                                node,self.__interface_list)
                        return self.__interface_list[1:]
                    else:
                        thread_list = []
                        for node in node_list:
                            x = threading.Thread(target=__threading_function,
                                                 args=((ACI_INTERFACE_L1_URL % (self.ip, node[2], node[1])),
                                                       ACI_INTERFACE_SYS_URL % (self.ip, node[2], node[1]),
                                                       ACI_INTERFACE_EP_URL % (self.ip, node[2], node[1]),
                                                       node[0]))
                            x.start()
                            thread_list.append(x)
                            if (threading.active_count() > 5):
                                time.sleep(1)
                        thread_waiter(thread_list)
                        return self.__interface_list[1:]

        def interface_policy(self):
            self.__interface_policy_list = []
            self.__interface_policy_list.append(
                interface_policy("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy"))
            url = ACI_INTERFACE_POLICY_URL % (self.ip)
            self.__calling(aci_func.interface_policy, url, self.__interface_policy_list)
            return self.__interface_policy_list[1:]

        def interface_policy_group_acc(self):
            self.__interface_polGrp_acc_list = []
            self.__interface_polGrp_acc_list.append(
                interface_policy_group_acc("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy"))
            url = ACI_INTERFACE_POLICY_GROUP_ACC_URL % (self.ip)
            self.__calling(aci_func.interface_policy_group_acc, url, self.__interface_polGrp_acc_list)
            return self.__interface_polGrp_acc_list[1:]

        def interface_policy_group_pc(self):
            self.__interface_polGrp_pc_list = []
            self.__interface_polGrp_pc_list.append(
                interface_policy_group_pc("dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy", "dummy"))
            url = ACI_INTERFACE_POLICY_GROUP_PC_URL % (self.ip)
            self.__calling(aci_func.interface_policy_group_pc, url, self.__interface_polGrp_pc_list)
            return self.__interface_polGrp_pc_list[1:]

        def interface_profile(self):
            self.__interface_profile_list = []
            self.__interface_profile_list.append(
                interface_profile_tuple("dummy", "dummy", "dummy", "dummy", "dummy"))
            url = ACI_INTERFACE_PROFILE_URL % (self.ip)
            self.__calling(aci_func.interface_profile, url, self.__interface_profile_list)
            return self.__interface_profile_list[1:]

        def switch_profile(self):
            self.__switch_profile_list = []
            self.__switch_profile_list.append(switch_profile_tuple("dummy", "dummy", "dummy"))
            url = ACI_SWITCH_PROFILE_URL % (self.ip)
            self.__calling(aci_func.switch_profile, url, self.__switch_profile_list)
            return self.__switch_profile_list[1:]

        def aep(self):
            self.__aep_list = []
            self.__aep_list.append(aep_tuple("dummy", "dummy"))
            url = ACI_AEP_URL % (self.ip)
            self.__calling(aci_func.aep, url, self.__aep_list)
            return self.__aep_list[1:]

        def domain(self):
            self.__domain_list = []
            self.__domain_list.append(domain_tuple("dummy"))
            url = ACI_DOMAIN_URL % (self.ip)
            self.__calling(aci_func.domain, url, self.__domain_list)
            url = ACI_DOMAIN_VMM_URL % (self.ip)
            self.__calling(aci_func.domain, url, self.__domain_list)
            return self.__domain_list[1:]

        def vlan_pool(self):
            self.__vlan_pool_list = []
            self.__vlan_pool_list.append(vlan_pool_tuple("dummy", "dummy", "dummy"))
            url = ACI_VLAN_POOL_URL % (self.ip)
            self.__calling(aci_func.vlan_pool, url, self.__vlan_pool_list)
            return self.__vlan_pool_list[1:]

        def unused_epg(self):
            all_ep = self.endpoints(_threading=True)
            all_epgs = self.epgs(_threading=True)
            for i in all_epgs:
                print(i)
            print(all_epgs)
            unused_epg = []
            for epg in all_epgs:
                for ep in all_ep:
                    if (
                            ep.tenant == epg.tenant and ep.ap == epg.ap_name and ep.epg == epg.epg_name and ep.ep_mac != ""):
                        break
                    elif (ep == all_ep[-1]):
                        unused_epg.append({"EPG_Tenant": epg.tenant, "AP_Name": epg.ap_name, "EPG_Name": epg.epg_name})
            return unused_epg

        def unused_bd(self):
            all_bds = self.bridge_domains(_threading=True)
            all_epgs = self.epgs(_threading=True)
            unused_bd = []
            for bd in all_bds:
                for epg in all_epgs:
                    if (bd.tenant == epg.epg_bd_bindings_tenant and bd.bd_name == epg.epg_bd_bindings):
                        break
                    elif (epg == all_epgs[-1]):
                        unused_bd.append({"BD_Name": bd.bd_name, "BD_Tenant": bd.tenant})
            return unused_bd

        def unused_vrf(self):
            all_bds = self.bridge_domains(_threading=True)
            all_l3s = self.L3out(_threading=True)
            all_vrfs = self.vrfs(_threading=True)
            unused_vrfs = []
            for vrf in all_vrfs:
                control = 0
                for bd in all_bds:
                    if (bd.bd_vrf == vrf.vrf_name and bd.bd_vrf_tenant == vrf.tenant):
                        control = 1
                        break
                for l3 in all_l3s:
                    if (l3.l3out_vrf == vrf.vrf_name and l3.l3out_vrf_tenant == vrf.tenant):
                        control = 1
                        break
                if control == 0:
                    unused_vrfs.append({"VRF_Name": vrf.vrf_name, "VRF_Tenant": vrf.tenant})
            return unused_vrfs

        def contracter(self, source_ip, destination_ip, port, protocol="tcp", _epg_selection=False):
            src = namedtuple("SRC", ("epg", "consumed_contracts", "provided_contracts"))
            dst = namedtuple("DST", ("epg", "consumed_contracts", "provided_contracts"))
            all_src, all_dst = [], []
            src_epg = self.endpoints(single_ep=source_ip)
            dst_epg = self.endpoints(single_ep=destination_ip)
            all_epg = self.epgs(_threading=True)
            all_contract = self.contract(_threading=True)
            all_filter = self.filter(_threading=True)
            print(src_epg)
            print(dst_epg)
            allowed_contracts = []
            for epg in all_epg:
                for _src in src_epg:
                    if (epg.ap_name == _src["ap"] and epg.epg_name == _src["epg"] and epg.tenant == _src["tenant"]):
                        all_src.append(src(epg.epg_name, epg.epg_contract_consumer, epg.epg_contract_provider))
                for _dst in dst_epg:
                    if (epg.ap_name == _dst["ap"] and epg.epg_name == _dst["epg"] and epg.tenant == _dst["tenant"]):
                        all_dst.append(dst(epg.epg_name, epg.epg_contract_consumer, epg.epg_contract_provider))
            if (not all_src):
                print("Source IP not found on ACI")
                return
            if (not all_dst):
                print("Destination IP not found on ACI")
                return
            if (_epg_selection):
                selection_src = all_src[list_printer([i.epg for i in all_src]) - 1]
                selection_dst = all_dst[list_printer([i.epg for i in all_dst]) - 1]
            else:
                selection_src = all_src[0]
                selection_dst = all_dst[0]
            for i in selection_src.consumed_contracts:
                for i2 in selection_dst.provided_contracts:
                    if (i.contract_name == i2.contract_name and i.contract_tenant == i2.contract_tenant):
                        allowed_contracts.append([i.contract_name, i.contract_tenant, "Consumed"])
            for i in selection_src.provided_contracts:
                for i2 in selection_dst.consumed_contracts:
                    if (i.contract_name == i2.contract_name and i.contract_tenant == i2.contract_tenant):
                        allowed_contracts.append([i.contract_name, i.contract_tenant, "Provided"])

            print(allowed_contracts)
            for i in allowed_contracts:
                for i2 in all_contract:
                    if (i[0] == i2.contract_name and i[1] == i2.contract_tenant):
                        for i3 in i2.contract_subjects:
                            for i4 in i3.subject_filter:
                                for i5 in all_filter:
                                    if (i4["FilterName"] == i5.filter_name and i4["FilterTenant"] == i5.filter_tenant):
                                        print(i5.filter_entries)
                                        for i6 in i5.filter_entries:
                                            if (i6.protocol == "unspecified"):
                                                if (i[2] == "Consumed"):
                                                    print("ALLOW")
                                                elif (i[2] == "Provided" and i3.subject_2way == "yes"):
                                                    print("ALLOW", "Provide")
                                            elif (i6.protocol == protocol):
                                                if (i6.dest_port_start == "unspecified" and
                                                        i6.dest_port_end == "unspecified"):
                                                    if (i[2] == "Consumed"):
                                                        print("ALLOW2")
                                                    elif (i[2] == "Provided" and i3.subject_2way == "yes"):
                                                        print("ALLOW2", "Provide")
                                                elif (int(i6.dest_port_start) <= port <= int(i6.dest_port_end)):
                                                    if (i[2] == "Consumed"):
                                                        print("ALLOW3")
                                                    elif (i[2] == "Provided" and i3.subject_2way == "yes"):
                                                        print("ALLOW3", "Provide")


def thread_waiter(thread_list):
    for i in thread_list:
        i.join()



