from Network.network import Network
import requests, json, sys
import threading
from Network.Constants_F5 import *
from collections import namedtuple
import re, time
from Network.F5.F5_functions import f5_functions as f5_func
from requests.auth import HTTPBasicAuth


class F5:
    class Rest_Api(Network):
        def __init__(self, ip: str, username: str, password: str, readonly: bool =True):
            if(readonly):
                self.headers = {
                    'content-type': "application/json",
                    'authorization': "Basic ZjVyZWFkb25seTp4a1lqVjhlUQ==",
                    'cache-control': "no-cache"
                }
            else:
                self.headers = {
                    'content-type': "application/json",
                    'authorization': "Basic dfgdgf",
                    'cache-control': "no-cache"
                }
            self.apic_cookie = {}
            super().__init__(ip)
            self.Locker = threading.Lock()
            #self.__get_rest__(username=username, password=password)
            self.thread_list = list()
            self.node_list = list()
            self.pool_list = list()
            self.vs_list = list()
            self.policy_list=list()
            self.poolstats_list =list()
            self.vsstats_list=list()
            self.configsync_list=list()
            self.irule_list=list()
            self.httpprofile_list=list()
            self.tcp_profile_list=list()
            self.udp_profile_list=list()
            self.fastl4_profile_list=list()
            self.persistence_list=list()
            self.cert_file_list=list()
            self.clientssl_list=list()
            self.clientssl_stats_list=list()
            self.serverssl_list=list()
            self.asm_list=list()
            self.asmsig_list = list()
        def __get_data__(self, url: str):
            try:
                print(self.headers)
                response = requests.get(url=url, headers=self.headers, verify=False)
            except requests.exceptions.ConnectTimeout:
                print("IP is not reachable. You need to call __get_rest__ function "
                      "again to continue")
                return
            if (response.status_code == 200):
                return response.json()
            else:
                print(response.status_code)
                print("Something went wrong while calling {}".format(url))
                return

        def __get_rest__(self, username: str, password: str) -> None:
            print(F5_AUTHENTICATION_URL % self.ip)
            try:
                auth = requests.post(url=F5_AUTHENTICATION_URL % self.ip,data=F5_AUTHENTICATION_DATA % (username, password),headers=self.headers,
                                     verify=False, timeout=5)
            except requests.exceptions.ConnectTimeout:
                print("IP is not reachable. You need to call __get_rest__ function "
                      "again to continue")
                sys.exit()
            response_conditions = {200: "Authentication Succesfull",
                                   401: "Authentication Failure"}

            if (auth.status_code == 200):
                print("Authentication Succesfull to {}".format(self.ip))
                auth_token = auth.json()['token']['token']
                self.headers["X-F5-Auth-Token"]=auth_token
                print(auth.json())
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

        def asm(self,attacksig=False,blocking_settings=False):
            asm_data_init = self.__get_data__(url=F5_ASM_URL_INIT % self.ip)
            datalist=list()
            datalist2 = list()
            datalist3 = list()
            looper = int(asm_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                asm_data_continue = self.__get_data__(url=F5_ASM_URL_CONTINUE % (self.ip,i*500))
                assert asm_data_continue is not None
                if(blocking_settings):
                    for id in asm_data_continue["items"]:
                        asm_blockingsettins_violations = self.__get_data__(url=F5_ASM_BLOCKING_SETTINGS_VIOLATIONS % (self.ip, id["id"]))
                        asm_blockingsettins_evasions = self.__get_data__(url=F5_ASM_BLOCKING_SETTINGS_EVASIONS % (self.ip, id["id"]))
                        asm_blockingsettins_http = self.__get_data__(url=F5_ASM_BLOCKING_SETTINGS_HTTP % (self.ip, id["id"]))
                        datalist3.append({"ID":id["id"],"Violations":asm_blockingsettins_violations,"Evasions":asm_blockingsettins_evasions,"HTTP":asm_blockingsettins_http})
                if(attacksig):
                    for id in asm_data_continue["items"]:
                        asmsig_data_init = self.__get_data__(url=F5_ASM_ASSIGNED_SIG_URL_INIT % (self.ip,id["id"]))
                        looper2 = int(asmsig_data_init["totalItems"] / 1000)
                        for i in range(looper2 + 1):
                            asmsig_data_continue = self.__get_data__(url=F5_ASM_ASSIGNED_SIG_URL_CONTINUE % (self.ip, id["id"],i * 1000))
                            assert asmsig_data_continue is not None
                            datalist2.append(asmsig_data_continue)
                datalist.append(asm_data_continue)
            self.asm_list = f5_func.asm(datalist,datalist2,datalist3)
            return self.asm_list

        def asm_signatures(self):
            asmsig_data_init = self.__get_data__(url=F5_ASM_SIG_URL_INIT % self.ip)
            datalist=list()
            looper = int(asmsig_data_init["totalItems"] / 1000)
            for i in range(looper + 1):
                asmsig_data_continue = self.__get_data__(url=F5_ASM_SIG_URL_CONTINUE % (self.ip,i*1000))
                assert asmsig_data_continue is not None
                datalist.append(asmsig_data_continue)
            self.asmsig_list = f5_func.asm_signatures(datalist)
            return self.asmsig_list

        def nodes(self):
            node_data_init = self.__get_data__(url=F5_NODE_URL_INIT % self.ip)
            datalist=list()
            looper = int(node_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                node_data_continue = self.__get_data__(url=F5_NODE_URL_CONTINUE % (self.ip,i*500))
                assert node_data_continue is not None
                datalist.append(node_data_continue)
            self.node_list = f5_func.nodes(datalist)
            return self.node_list
        
        def pools(self):
            pool_data_init = self.__get_data__(url=F5_POOL_URL_INIT % self.ip)
            datalist=list()
            looper = int(pool_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                pool_data_continue = self.__get_data__(url=F5_POOL_URL_CONTINUE % (self.ip,i*500))
                assert pool_data_continue is not None
                datalist.append(pool_data_continue)
            self.pool_list = f5_func.pools(datalist)
            return self.pool_list

        def irule(self):
            irule_data_init = self.__get_data__(url=F5_IRULE_URL_INIT % self.ip)
            datalist=list()
            looper = int(irule_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                irule_data_continue = self.__get_data__(url=F5_IRULE_URL_CONTINUE % (self.ip,i*500))
                assert irule_data_continue is not None
                datalist.append(irule_data_continue)
            self.irule_list = f5_func.irule(datalist)
            return self.irule_list

        def configsync(self,devicegroup):
            print(F5_CONFIGSYNC_URL % (self.ip,devicegroup))
            sync_data = self.__get_data__(url=F5_CONFIGSYNC_URL % (self.ip,devicegroup))
            datalist=list()
            assert sync_data is not None
            datalist.append(sync_data)
            self.configsync_list = f5_func.configsync(datalist)
            return self.configsync_list

        def virtualservers(self):
            vs_data_init = self.__get_data__(url=F5_VS_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_VS_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.vs_list = f5_func.virtualservers(datalist)
            return self.vs_list

        def policy(self):
            policy_data_init = self.__get_data__(url=F5_POLICY_URL_INIT % self.ip)
            datalist=list()
            looper = int(policy_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                policy_data_continue = self.__get_data__(url=F5_POLICY_URL_CONTINUE % (self.ip,i*500))
                assert policy_data_continue is not None
                datalist.append(policy_data_continue)
            self.policy_list = f5_func.policy(datalist)
            return self.policy_list

        def stats_pool(self):
            poolstats_data_init = self.__get_data__(url=F5_POOLSTATS_URL_INIT % self.ip)
            datalist=list()
            looper = int(poolstats_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                poolstats_data_continue = self.__get_data__(url=F5_POOLSTATS_URL_CONTINUE % (self.ip,i*500))
                assert poolstats_data_continue is not None
                datalist.append(poolstats_data_continue)
            self.poolstats_list = f5_func.stats_pool(datalist)
            return self.poolstats_list

        def stats_virtual(self):
            virtualstats_data_init = self.__get_data__(url=F5_VIRTUALSTATS_URL_INIT % self.ip)
            datalist=list()
            looper = int(virtualstats_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                virtualstats_data_continue = self.__get_data__(url=F5_VIRTUALSTATS_URL_CONTINUE % (self.ip,i*500))
                assert virtualstats_data_continue is not None
                datalist.append(virtualstats_data_continue)
            self.vsstats_list = f5_func.stats_virtual(datalist)
            return self.vsstats_list

        def stats_virtualprofiles(self):
            if(self.vs_list):
                pass
            else:
                self.virtualservers()
            for i in self.vs_list:
                virtualprofilestats_data = self.__get_data__(url=F5_VIRTUALPROFILESTATS_URL % (self.ip,i.VS_Partition,i.VS_Name))
                datalist=list()
                assert virtualprofilestats_data is not None
                datalist.append(virtualprofilestats_data)
                self.vsstats_list.append(f5_func.stats_virtualprofiles(datalist,i.VS_Name,i.VS_Partition))
            return self.vsstats_list

        def clientssl_profile(self):
            vs_data_init = self.__get_data__(url=F5_CLIENTSSL_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_CLIENTSSL_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.clientssl_list = f5_func.clientssl_profile(datalist)
            return self.clientssl_list

        def clientssl_profile_stats(self):
            vs_data_init = self.__get_data__(url=F5_CLIENTSSLSTATS_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_CLIENTSSLSTATS_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.clientssl_stats_list = f5_func.clientssl_profile_stats(datalist)
            return self.clientssl_stats_list

        def serverssl_profile(self):
            vs_data_init = self.__get_data__(url=F5_SERVERSSL_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_SERVERSSL_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.serverssl_list = f5_func.serverssl_profile(datalist)
            return self.serverssl_list

        def http_profile(self):
            vs_data_init = self.__get_data__(url=F5_HTTPPROFILE_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_HTTPPROFILE_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.httpprofile_list = f5_func.http_profile(datalist)
            return self.httpprofile_list

        def tcp_profile(self):
            vs_data_init = self.__get_data__(url=F5_TCPPROFILE_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_TCPPROFILE_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.tcp_profile_list = f5_func.tcp_profile(datalist)
            return self.tcp_profile_list

        def udp_profile(self):
            vs_data_init = self.__get_data__(url=F5_UDPPROFILE_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_UDPPROFILE_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.udp_profile_list = f5_func.udp_profile(datalist)
            return self.udp_profile_list

        def fastl4_profile(self):
            vs_data_init = self.__get_data__(url=F5_FASTL4PROFILE_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_FASTL4PROFILE_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.fastl4_profile_list = f5_func.fastl4_profile(datalist)
            return self.fastl4_profile_list

        def persistence(self):
            list1=[
                [F5_COOKIEPERSIST_URL_INIT,F5_COOKIEPERSIST_URL_CONTINUE],
                [F5_SRCPERSIST_URL_INIT,F5_SRCPERSIST_URL_CONTINUE],
                [F5_UNIVERSALPERSIST_URL_INIT,F5_UNIVERSALPERSIST_URL_CONTINUE],
                [F5_SSLPERSIST_URL_INIT,F5_SSLPERSIST_URL_CONTINUE]
            ]
            named_tuple_persistence = namedtuple("Persistence",
                                                 ("Type", "PersistenceName", "PersistencePartition", "CookieName",
                                                  "Encryption", "Timeout", "Mirror", "Irule"))
            self.persistence_list=[named_tuple_persistence("dummy","dummy","dummy","dummy","dummy","dummy","dummy",
                                                           "dummy")]
            for o in list1:
                vs_data_init = self.__get_data__(url=o[0] % self.ip)
                datalist=list()
                looper = int(vs_data_init["totalItems"] / 500)
                for i in range(looper + 1):
                    vs_data_continue = self.__get_data__(url=o[1] % (self.ip,i*500))
                    assert vs_data_continue is not None
                    datalist.append(vs_data_continue)
                self.persistence_list += f5_func.persistence(datalist)
            return self.persistence_list[1:]

        def certfiles(self):
            vs_data_init = self.__get_data__(url=F5_CERTFILES_URL_INIT % self.ip)
            datalist=list()
            looper = int(vs_data_init["totalItems"] / 500)
            for i in range(looper + 1):
                vs_data_continue = self.__get_data__(url=F5_CERTFILES_URL_CONTINUE % (self.ip,i*500))
                assert vs_data_continue is not None
                datalist.append(vs_data_continue)
            self.cert_file_list = f5_func.certfiles(datalist)
            return self.cert_file_list

        def wide_ip(self):
            wide_ip_init = self.__get_data__(url=F5_WIDEIP_URL_INIT % self.ip)
            datalist=list()
            looper = int(wide_ip_init["totalItems"] / 500)
            for i in range(looper + 1):
                data_continue = self.__get_data__(url=F5_WIDEIP_URL_CONTINUE % (self.ip,i*500))
                assert data_continue is not None
                datalist.append(data_continue)
            self.wide_ip_list = f5_func.wide_ip(datalist)
            return self.wide_ip_list
        def gtm_servers(self):
            gtm_servers_init = self.__get_data__(url=F5_GTMSERVERS_URL_INIT % self.ip)
            datalist=list()
            looper = int(gtm_servers_init["totalItems"] / 500)
            for i in range(looper + 1):
                data_continue = self.__get_data__(url=F5_GTMSERVERS_URL_CONTINUE % (self.ip,i*500))
                assert data_continue is not None
                datalist.append(data_continue)
            self.gtm_servers_list = f5_func.gtm_servers(datalist)
            return self.gtm_servers_list
        def gtm_pools(self):
            gtm_pools_init = self.__get_data__(url=F5_GTMPOOLS_URL_INIT % self.ip)
            datalist=list()
            looper = int(gtm_pools_init["totalItems"] / 500)
            for i in range(looper + 1):
                data_continue = self.__get_data__(url=F5_GTMPOOLS_URL_CONTINUE % (self.ip,i*500))
                assert data_continue is not None
                datalist.append(data_continue)
            self.gtm_pools_list = f5_func.gtm_pools(datalist)
            return self.gtm_pools_list
