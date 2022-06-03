from collections import namedtuple
from pprint import pprint
import threading
from Network.Constants_F5 import *


class f5_functions:
    @staticmethod
    def nodes(datalist):
        named_tuple_nodes = namedtuple("Node", ("NodeName", "NodePartition", "NodeIP","MemberState","MemberAdminState"))
        dummy_list = list()
        for data in datalist:
            for node in data["items"]:
                dummy_list.append(named_tuple_nodes(node["name"], node["partition"], node["address"],
                                                   node["state"],node["session"]))
        return dummy_list

    @staticmethod
    def pools(datalist):
        named_tuple_pool = namedtuple("Pool", ("PoolName", "PoolPartition", "LBMethod", "ServiceDownAction",
                                               "SlowRampTime", "PriorityGroupActivation", "HealthMonitor",
                                               "PoolMembers"))
        named_tuple_members = namedtuple("Members", ("MemberIP", "MemberPort", "MemberConnLimit", "MemberPartition",
                                                     "MemberPriorityGroup", "MemberRatio", "MemberState",
                                                     "MemberAdminState",
                                                     "MemberSelfLink"))
        dummy_list = list()
        for data in datalist:
            for pool in data["items"]:
                # pprint(pool)
                member_list = list()
                monitorlist = list()
                if ("items" in pool["membersReference"]):
                    for member in pool["membersReference"]["items"]:
                        dummy = named_tuple_members(member["address"], member["name"].split(":")[1],
                                                    member["connectionLimit"],
                                                    member["partition"], member["priorityGroup"], member["ratio"],
                                                    member["state"],
                                                    member["session"], member["selfLink"])
                        member_list.append(dummy)
                if ("monitor" in pool):
                    monitorlist = pool["monitor"].split(" and ")
                if (pool["minActiveMembers"] != 0):
                    prioritygroup = str(pool["minActiveMembers"])
                else:
                    prioritygroup = "N/A"
                dummy_list.append(named_tuple_pool(pool["name"], pool["partition"], pool["loadBalancingMode"],
                                                   pool["serviceDownAction"],
                                                   pool["slowRampTime"], prioritygroup, monitorlist, member_list))
        return dummy_list

    @staticmethod
    def stats_pool(datalist):
        named_tuple_poolstats = namedtuple("PoolStats",
                                           ("PoolName", "PoolPartition", "TotalConnection", "Availability"))
        dummy_list = list()
        for data in datalist:
            for pool in data["entries"].keys():
                poolname = data["entries"][pool]["nestedStats"]["entries"]["tmName"]["description"].split("/")[-1]
                poolpartition = data["entries"][pool]["nestedStats"]["entries"]["tmName"]["description"].split("/")[-2]
                total_conn = str(data["entries"][pool]["nestedStats"]["entries"]["serverside.totConns"]["value"])
                pool_status = data["entries"][pool]["nestedStats"]["entries"]["status.availabilityState"]["description"]
                dummy_list.append(named_tuple_poolstats(poolname, poolpartition, total_conn, pool_status))
        return dummy_list

    @staticmethod
    def stats_virtual(datalist):
        named_tuple_vsstats = namedtuple("VirtualStats", ("VSName", "VSPartition", "TotalConnection", "Availability"))
        dummy_list = list()
        for data in datalist:
            for vs in data["entries"].keys():
                vsname = data["entries"][vs]["nestedStats"]["entries"]["tmName"]["description"].split("/")[-1]
                vspartition = data["entries"][vs]["nestedStats"]["entries"]["tmName"]["description"].split("/")[-2]
                total_conn = str(data["entries"][vs]["nestedStats"]["entries"]["clientside.totConns"]["value"])
                vs_status = data["entries"][vs]["nestedStats"]["entries"]["status.availabilityState"]["description"]
                dummy_list.append(named_tuple_vsstats(vsname, vspartition, total_conn, vs_status))
        return dummy_list

    @staticmethod
    def stats_virtualprofiles(datalist,vs,vs_partition):
        named_tuple_vsprofilestats = namedtuple("VirtualProfileStats", ("VSName", "VSPartition", "Count2XX", "Count4XX", "Count5XX" ))
        dummy_list = list()
        for data in datalist:
            for vsprofile in data["entries"].keys():
                vsprof_type = data["entries"][vsprofile]["nestedStats"]["entries"]["typeId"]["description"]
                if(vsprof_type=="ltm profile http"):
                    count2XX = data["entries"][vsprofile]["nestedStats"]["entries"]["resp_2xxCnt"]["value"]
                    count4XX = data["entries"][vsprofile]["nestedStats"]["entries"]["resp_4xxCnt"]["value"]
                    count5XX = data["entries"][vsprofile]["nestedStats"]["entries"]["resp_5xxCnt"]["value"]
                    dummy_list.append(named_tuple_vsprofilestats(vs, vs_partition, count2XX, count4XX, count5XX))
                else:
                    continue
        return dummy_list

    @staticmethod
    def irule(datalist):
        named_tuple_irule = namedtuple("irule", ("IruleName", "IrulePartition", "IruleCode", "IruleVerification"))
        dummy_list = list()
        for data in datalist:
            for irule in data["items"]:
                irulename = irule["name"]
                irulepartition = irule["partition"]
                if("apiAnonymous" in irule):
                    irulecode = str(irule["apiAnonymous"])
                else:
                    irulecode = ""
                iruleverification = "F5_Verified" if "apiRawValues" in irule else "User_Defined"
                dummy_list.append(named_tuple_irule(irulename, irulepartition, irulecode, iruleverification))
        return dummy_list

    @staticmethod
    def configsync(datalist):
        named_tuple_configsync = namedtuple("ConfigSync", ("Device", "CommitTime"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["entries"].keys():
                device_name = data["entries"][data2]["nestedStats"]["entries"]["device"]["description"]
                commit_time = data["entries"][data2]["nestedStats"]["entries"]["commitIdTime"]["description"]
                dummy_list.append(named_tuple_configsync(device_name, commit_time))
        # print(dummy_list)
        return dummy_list

    @staticmethod
    def clientssl_profile(datalist):
        named_tuple_clientssl = namedtuple("ClientSSL", (
            "ProfileName", "ProfilePartition", "KeyName", "CertName", "Chain", "CipherGroup", "Ciphers","ParentProfileName","ParentProfilePartition"))
        dummy_list = list()
        for data in datalist:
            for clientssl in data["items"]:
                chain, key_name, cert_name, cipher_group, ciphers = "", "", "", "", ""
                profile_name = clientssl["name"]
                profile_partition = clientssl["partition"]
                if ("defaultsFrom" in clientssl):
                    if(clientssl["defaultsFrom"]!="none"):
                        default_profile_name = clientssl["defaultsFrom"].split("/")[-1]
                        default_profile_partition = clientssl["defaultsFrom"].split("/")[-2]
                    else:
                        default_profile_name="None"
                        default_profile_partition="None"
                if ("key" in clientssl):
                    key_name = clientssl["key"]
                if ("cert" in clientssl):
                    cert_name = clientssl["cert"]
                if ("chain" in clientssl):
                    chain = clientssl["chain"]
                if ("cipherGroup" in clientssl):
                    cipher_group = clientssl["cipherGroup"]
                if ("ciphers" in clientssl):
                    ciphers = clientssl["ciphers"]
                dummy_list.append(
                    named_tuple_clientssl(profile_name, profile_partition, key_name, cert_name, chain, cipher_group,
                                          ciphers,default_profile_name,default_profile_partition))
        return dummy_list

    @staticmethod
    def clientssl_profile_stats(datalist):
        named_tuple_clientsslstats = namedtuple("ClientSSLStats", ("ProfileName", "ProfilePartition", "SSLv2", "SSLv3",
                                                                   "TLSv1_0", "TLSv1_1", "TLSv1_2"))
        dummy_list = list()
        for data in datalist:
            for clientssl in data["entries"].keys():
                profile_name = data["entries"][clientssl]["nestedStats"]["entries"]["tmName"]["description"].split("/")[
                    -1]
                profile_partition = \
                    data["entries"][clientssl]["nestedStats"]["entries"]["tmName"]["description"].split("/")[-2]
                count_sslv2 = str(
                    data["entries"][clientssl]["nestedStats"]["entries"]["common.protocolUses.sslv2"]["value"])
                count_sslv3 = str(
                    data["entries"][clientssl]["nestedStats"]["entries"]["common.protocolUses.sslv3"]["value"])
                count_tls1_0 = str(
                    data["entries"][clientssl]["nestedStats"]["entries"]["common.protocolUses.tlsv1"]["value"])
                count_tls1_1 = str(
                    data["entries"][clientssl]["nestedStats"]["entries"]["common.protocolUses.tlsv1_1"]["value"])
                count_tls1_2 = str(
                    data["entries"][clientssl]["nestedStats"]["entries"]["common.protocolUses.tlsv1_2"]["value"])
                dummy_list.append(
                    named_tuple_clientsslstats(profile_name, profile_partition, count_sslv2, count_sslv3, count_tls1_0,
                                               count_tls1_1, count_tls1_2))

        return dummy_list

    @staticmethod
    def http_profile(datalist):
        named_tuple_httpprofile = namedtuple("HTTPProfile", ("ProfileName", "ProfilePartition", "XFF", "MaxHeaderSize"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                name = data2["name"]
                partition = data2["partition"]
                xff = data2["insertXforwardedFor"]
                maxheadersize = data2["enforcement"]["maxHeaderSize"]
                dummy_list.append(named_tuple_httpprofile(name, partition, xff, maxheadersize))
        return dummy_list

    @staticmethod
    def tcp_profile(datalist):
        named_tuple_tcpprofile = namedtuple("TCPProfile", ("ProfileName", "ProfilePartition", "IdleTimeout"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                name = data2["name"]
                partition = data2["partition"]
                idletimeout = data2["idleTimeout"]
                dummy_list.append(named_tuple_tcpprofile(name, partition, idletimeout))
        return dummy_list

    @staticmethod
    def udp_profile(datalist):
        named_tuple_udpprofile = namedtuple("UDPProfile", ("ProfileName", "ProfilePartition", "IdleTimeout"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                name = data2["name"]
                partition = data2["partition"]
                idletimeout = data2["idleTimeout"]
                dummy_list.append(named_tuple_udpprofile(name, partition, idletimeout))
        return dummy_list

    @staticmethod
    def fastl4_profile(datalist):
        named_tuple_fastl4profile = namedtuple("FastL4Profile", ("ProfileName", "ProfilePartition", "IdleTimeout"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                name = data2["name"]
                partition = data2["partition"]
                idletimeout = data2["idleTimeout"]
                dummy_list.append(named_tuple_fastl4profile(name, partition, idletimeout))
        return dummy_list

    @staticmethod
    def persistence(datalist):
        named_tuple_persistence = namedtuple("Persistence",
                                             ("Type", "PersistenceName", "PersistencePartition", "CookieName",
                                              "Encryption", "Timeout", "Mirror", "Irule"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                type = data2["kind"].split(":")[-2]
                name = data2["name"]
                partition = data2["partition"]
                cookie_name = "N/A"
                cookie_encry = "N/A"
                mirror = "N/A"
                irule = "N/A"
                if (type == "cookie"):
                    cookie_name = data2["cookieName"] if data2["cookieName"] != "none" else "DEFAULT"
                    cookie_encry = data2["cookieEncryption"]
                    timeout = "Session"
                elif (type == "universal"):
                    timeout = data2["timeout"]
                    irule = data2["rule"]
                    mirror = data2["mirror"]
                else:
                    timeout = data2["timeout"]
                    mirror = data2["mirror"]
                dummy_list.append(
                    named_tuple_persistence(type, name, partition, cookie_name, cookie_encry, timeout, mirror, irule))
        return dummy_list

    @staticmethod
    def certfiles(datalist):
        named_tuple_certfiles = namedtuple("CertFiles", ("CertName", "CertPartition", "ExpiredDate"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                name = data2["name"]
                partition = data2["partition"]
                expired_date = data2["expirationString"]
                dummy_list.append(named_tuple_certfiles(name, partition, expired_date))
        return dummy_list

    @staticmethod
    def asm(datalist,datalist2,datalist3):
        named_tuple_asm = namedtuple("ASM", ("PolicyName", "PolicyPartition", "VirtualServers", "Enforcement","ID","AssignedAttackSignatures","BlockingSettings"))
        named_tuple_asmsig = namedtuple("ASMAssignedSig", ("SigID", "Block", "Staging", "Enabled"))
        named_tuple_blockingsettings = namedtuple("ASMBlockingSettings", ("Name", "Alarm", "Learn", "Block","Type","Enabled"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                assigned_attack_signatures = list()
                blocking_settings = list()
                name = data2["name"]
                id = data2["id"]
                partition = data2["partition"]
                policy_type=data2["type"]
                if(policy_type=="security"):
                    enforcement = data2["enforcementMode"]
                else:
                    enforcement = ""
                vs_list=list()
                if ("virtualServers" in data2):
                    for m2 in data2["virtualServers"]:
                        vs_list.append(m2)
                if ("manualVirtualServers" in data2):
                    for m2 in data2["manualVirtualServers"]:
                        vs_list.append(m2)
                if(datalist2):
                    for dataa in datalist2:
                        for dataa2 in dataa["items"]:
                            if([k for k in dataa2["selfLink"].split("/") if id in k]):
                                staging="N/A"
                                if("performStaging" in dataa2):
                                    staging=dataa2["performStaging"]
                                assigned_attack_signatures.append(named_tuple_asmsig(dataa2["signatureReference"]["signatureId"],dataa2["block"],
                                                                               staging,dataa2["enabled"]))
                if(datalist3):
                    for dataa in datalist3:
                        if(id!=dataa["ID"]):continue
                        for violations in dataa["Violations"]["items"]:
                            desc=violations["description"]
                            alarm = violations["alarm"] if("alarm" in violations) else "N/A"
                            learn = violations["learn"] if("learn" in violations) else "N/A"
                            block = violations["block"] if ("block" in violations) else "N/A"
                            blocking_settings.append(named_tuple_blockingsettings(desc,alarm,learn,block,"Violations","N/A"))
                        for evasions in dataa["Evasions"]["items"]:
                            desc=evasions["description"]
                            learn = evasions["learn"] if("learn" in evasions) else "N/A"
                            enabled = evasions["enabled"] if ("enabled" in evasions) else "N/A"
                            blocking_settings.append(named_tuple_blockingsettings(desc,"N/A",learn,"N/A","Evasions",enabled))
                        for httpcompliance in dataa["HTTP"]["items"]:
                            desc=httpcompliance["description"]
                            learn = httpcompliance["learn"] if("learn" in httpcompliance) else "N/A"
                            enabled = httpcompliance["enabled"] if ("enabled" in httpcompliance) else "N/A"
                            blocking_settings.append(named_tuple_blockingsettings(desc,"N/A",learn,"N/A","HTTPCompliance",enabled))
                dummy_list.append(named_tuple_asm(name, partition, vs_list, enforcement,id,assigned_attack_signatures,blocking_settings))
        return dummy_list

    @staticmethod
    def asm_signatures(datalist):
        named_tuple_asmsignatures = namedtuple("ASMSignatures", ("AttackSigID", "AttackSigName", "AttackSigDesc","AttackSigRev","AttackSigType"))
        dummy_list = list()
        for data in datalist:
            for data2 in data["items"]:
                name = data2["name"]
                id = data2["id"]
                desc = data2["description"]
                revision_no=data2["revision"]
                attack_type = data2["attackTypeReference"]["name"]
                dummy_list.append(named_tuple_asmsignatures(id,name, desc,revision_no,attack_type))
        return dummy_list

    @staticmethod
    def serverssl_profile(datalist):
        named_tuple_serversslprofile = namedtuple("ServerSSL",
                                                  ("ProfileName", "ProfilePartition", "CipherGroup", "Ciphers"))
        dummy_list = list()
        cipher_group, ciphers = "", ""
        for data in datalist:
            for data2 in data["items"]:
                name = data2["name"]
                partition = data2["partition"]
                if ("cipherGroup" in data2):
                    cipher_group = data2["cipherGroup"]
                if ("ciphers" in data2):
                    ciphers = data2["ciphers"]
                dummy_list.append(named_tuple_serversslprofile(name, partition, cipher_group, ciphers))
        return dummy_list

    @staticmethod
    def wide_ip(datalist):
        named_tuple_wide_ip = namedtuple("WideIP", ("DNS", "Partition", "Pool", "State"))
        named_tuple_dns_pool = namedtuple("DNSPools", ("PoolName", "Partition", "Order"))
        dummy_list = list()
        for data in datalist:
            for wide_ip in data["items"]:
                pools = []
                dns = wide_ip["name"]
                partition = wide_ip["partition"]
                state = wide_ip["enabled"]
                if ("pools" in wide_ip):
                    for i in wide_ip["pools"]:
                        pools.append(named_tuple_dns_pool(i["name"], i["partition"], i["order"]))
                dummy_list.append(named_tuple_wide_ip(dns, partition, pools, state))
        return dummy_list

    @staticmethod
    def gtm_servers(datalist):
        named_tuple_server = namedtuple("GTMServer", ("GTMServerName", "Partition", "Type", "VS"))
        named_tuple_vs = namedtuple("GTMVS", ("VSName", "VSIP", "VSPort"))
        dummy_list = list()
        for data in datalist:
            for server in data["items"]:
                vs = []
                gtm_server_name = server["name"]
                partition = server["partition"]
                type = server["product"]
                if ("virtualServersReference" in server):
                    for i in server["virtualServersReference"]["items"]:
                        ip = i["destination"].split(":")[0]
                        port = i["destination"].split(":")[1]
                        vs.append(named_tuple_vs(i["name"], ip, port))
                dummy_list.append(named_tuple_server(gtm_server_name, partition, type, vs))
        return dummy_list

    @staticmethod
    def gtm_pools(datalist):
        named_tuple_gtm_pool = namedtuple("GTMPool", (
            "GTMPoolName", "Partition", "LBMethod", "AlternateMethod", "FallbackMethod", "FallbackIP", "TTL",
            "Members"))
        named_tuple_gtm_poolmember = namedtuple("GTMPoolMember", ("MemberName", "GTMServerName", "MemberState"))
        dummy_list = list()
        for data in datalist:
            for pool in data["items"]:
                member_list = []
                gtm_pool_name = pool["name"]
                partition = pool["partition"]
                lb_method = pool["loadBalancingMode"]
                alternate_method = pool["alternateMode"]
                fallback_method = pool["fallbackMode"]
                fallback_ip = pool["fallbackIp"]
                ttl = pool["ttl"]
                if ("membersReference" in pool):
                    if ("items" in pool["membersReference"]):
                        for i in pool["membersReference"]["items"]:
                            member_name = "/" + i["fullPath"].split("/")[-2] + "/" + i["name"]
                            gtm_server_name = i["fullPath"].split("/")[2].replace(":", "")
                            if("enabled" in i):
                                member_status=str(i["enabled"])
                            else:
                                member_status=str(i["disabled"])
                            member_list.append(named_tuple_gtm_poolmember(member_name, gtm_server_name, member_status))
                dummy_list.append(
                    named_tuple_gtm_pool(gtm_pool_name, partition, lb_method, alternate_method, fallback_method,
                                         fallback_ip, ttl, member_list))
        return dummy_list

    @staticmethod
    def virtualservers(datalist):
        named_tuple_vs = namedtuple("VS", (
            "VS_Name", "VS_Partition", "VS_IP", "VS_Port", "VS_DefaultPool", "VS_DefaultPoolPartition","VS_Irules", "VS_Persistence",
            "VS_Dos", "VS_TcpClient", "VS_TcpServer", "VS_UdpClient", "VS_UdpServer", "VS_F4Client", "VS_F4Server",
            "VS_ClientSSL", "VS_ServerSSL", "VS_SNAT", "VS_Mirror",
            "VS_OneConnect", "VS_Policies", "HTTPProfile", "IPForward","LastChange","CreationTime"))
        dummy_list = list()
        for data in datalist:
            for vs in data["items"]:
                vs_ipport = vs["destination"].replace(vs["partition"], "").replace("/", "").split(":")
                irulelist, persist = list(), "None"
                botdefense="None"
                dos, http, tcpClient, tcpServer = "None", "None", "None", "None"
                clientSSL, serverSSL, oneConnect, ipforward = [], [], "None", "None"
                udpClient, udpServer = "None", "None"
                f4Client, f4Server = "None", "None"
                snat, mirror = "None", "None"
                pool = "None"
                pool_partition = "None"
                lastModifiedTime, creationTime = "None", "None"
                policylist = list()
                # pprint(vs)
                if ("lastModifiedTime" in vs):
                    lastModifiedTime = vs["lastModifiedTime"] if("1970-" not in vs["lastModifiedTime"]) else "unknown"
                if ("creationTime" in vs):
                    creationTime = vs["creationTime"] if("1970-" not in vs["creationTime"]) else "unknown"
                if ("ipForward" in vs):
                    ipforward = "True"
                if ("pool" in vs):
                    pool = vs["pool"].split("/")[-1]
                    pool_partition = vs["pool"].split("/")[-2]
                if ("rules" in vs):
                    for m in vs["rules"]:
                        irulelist.append(m)
                if ("persist" in vs):
                    persisttype = "Unknown"
                    for m in vs["persist"]:
                        if ("nameReference" in m):
                            persisttype = \
                                m["nameReference"]["link"].replace("https://localhost/mgmt/tm/ltm/persistence/",
                                                                   "").split(
                                    "/")[0]
                        persist = (m["name"] )#+ "(" + persisttype + ")")
                if ("sourceAddressTranslation" in vs):
                    snat = vs["sourceAddressTranslation"]["type"]
                if ("mirror" in vs):
                    mirror = vs["mirror"]
                if ("profilesReference" in vs):

                    for m2 in vs["profilesReference"]["items"]:
                        if ("nameReference" in m2):
                            profiletype = m2["nameReference"]["link"].replace("https://localhost/mgmt/tm/ltm/profile/",
                                                                              "")
                            profiletype = profiletype.replace("https://localhost/mgmt/tm/security/", "").split("/")[0]
                            if (profiletype == "one-connect"):
                                oneConnect = m2["name"]
                            if (profiletype == "client-ssl"):
                                clientSSL.append(m2["name"])
                            if (profiletype == "server-ssl"):
                                serverSSL.append(m2["name"])
                            if (profiletype == "dos"):
                                dos = m2["name"]
                            if (profiletype == "http"):
                                http = m2["name"]
                            if (profiletype == "tcp"):
                                if (m2["context"] == "all"):
                                    tcpClient, tcpServer = m2["name"], m2["name"]
                                elif (m2["context"] == "clientside"):
                                    tcpClient = m2["name"]
                                elif (m2["context"] == "serverside"):
                                    tcpServer = m2["name"]
                            if (profiletype == "udp"):
                                if (m2["context"] == "all"):
                                    udpClient, udpServer = m2["name"], m2["name"]
                                elif (m2["context"] == "clientside"):
                                    udpClient = m2["name"]
                                elif (m2["context"] == "serverside"):
                                    udpServer = m2["name"]
                            if (profiletype == "fastl4"):
                                if (m2["context"] == "all"):
                                    f4Client, f4Server = m2["name"], m2["name"]
                                elif (m2["context"] == "clientside"):
                                    f4Client = m2["name"]
                                elif (m2["context"] == "serverside"):
                                    f4Server = m2["name"]
                if ("policiesReference" in vs):
                        if ("items" in vs["policiesReference"]):
                            for m2 in vs["policiesReference"]["items"]:
                                policylist.append(m2["name"])

                dummy_list.append(named_tuple_vs(vs["name"], vs["partition"], vs_ipport[0].split("%")[0], vs_ipport[1],
                                                 pool, pool_partition, irulelist, persist, dos, tcpClient, tcpServer, udpClient, udpServer,
                                                 f4Client,f4Server,clientSSL,serverSSL,snat,mirror,
                                                 oneConnect, policylist, http, ipforward,lastModifiedTime,creationTime))
        return dummy_list

    @staticmethod
    def policy(datalist):
        dummy_list = list()
        for data in datalist:
            for policy in data["items"]:
                named_tuple_rule_list = namedtuple("Policy", ("PolicyName", "PolicyPartition", "Condition", "Action"))
                rule_actions_list = list()
                rule_conditions_list = list()
                condition_list = list()
                action_list = list()
                all_actions = list()

                if ("rulesReference" in policy):

                    if ("items" in policy["rulesReference"]):
                        condition_list = list()
                        action_list = list()
                        for m2 in policy["rulesReference"]["items"]:

                            rule_name = m2["name"]
                            rule_index = m2["ordinal"]
                            named_tuple_ruleaction = namedtuple("RuleAction",
                                                                ("Operation", "Type", "action1", "action2"))
                            named_tuple_rulecondition = namedtuple("RuleCondition",
                                                                   ("Operation", "condition1", "condition2", "value"))
                            condition = namedtuple("Condition", ("RuleName", "RuleIndex", "RuleConditon"))
                            action = namedtuple("Action", ("RuleName", "RuleIndex", "RuleAction"))
                            rule_actions_list = list()
                            if ("actionsReference" in m2):
                                rule_actions = ""
                                if ("items" in m2["actionsReference"]):
                                    rule_actions_list = list()
                                    hold1 = 1
                                    name = ""
                                    con1 = []
                                    for m3 in m2["actionsReference"]["items"]:
                                        if ("enable" in m3):
                                            con1 = [["cache", "", ""], ["compress", "", ""], ["avr", "", ""],
                                                    ["asm", "", ""],
                                                    ["decompress", "", ""], ["http", "", ""],
                                                    ["l7dos", "fromProfile", ""],
                                                    ["requestAdapt", "", ""], ["responseAdapt", "", ""],
                                                    ["serverSsl", "", ""]];
                                            operation = "Enabled"
                                        elif ("disable" in m3):
                                            con1 = [["cache", "", ""], ["compress", "", ""], ["avr", "", ""],
                                                    ["asm", "", ""],
                                                    ["decompress", "", ""], ["http", "", ""],
                                                    ["l7dos", "fromProfile", ""],
                                                    ["requestAdapt", "", ""], ["responseAdapt", "", ""],
                                                    ["serverSsl", "", ""]];
                                            operation = "Disabled"
                                        elif ("forward" in m3):
                                            con1 = [["pool", "pool", ""], ["node", "node", ""],
                                                    ["virtual", "virtual", ""]];
                                            operation = "Forwarding"
                                        elif ("insert" in m3):
                                            con1 = [["httpCookie", "tmName", ""], ["httpHeader", "tmName", ""],
                                                    ["httpReferer", "value", ""],
                                                    ["httpSetCookie", "tmName", "value"]];
                                            operation = "Inserting"
                                        elif ("remove" in m3):
                                            con1 = [["httpCookie", "tmName", ""], ["httpHeader", "tmName", ""],
                                                    ["httpReferer", "", ""], ["httpSetCookie", "tmName", ""]];
                                            operation = "Removing"
                                        elif ("replace" in m3):
                                            con1 = [["httpHeader", "tmName", "value"], ["httpHost", "value", ""],
                                                    ["httpReferer", "value", ""], ["httpUri", "path", "value"],
                                                    ["httpUri", "queryString", "value"]];
                                            operation = "Replacing"
                                        elif ("redirect" in m3):
                                            con1 = [["location", "location", ""]];
                                            operation = "Redirecting"
                                        elif ("reset" in m3):
                                            con1 = [["", "", ""]];
                                            operation = "ResetTraffic"
                                        elif ("log" in m3):
                                            con1 = [["message", "", ""]];
                                            operation = "Logging"
                                        else:
                                            rule_actions += "NOT FOUND;;";
                                            operation = "None"
                                        for m33 in con1:
                                            if ("" == m33[0]):
                                                rule_actions_list.append(
                                                    named_tuple_ruleaction(operation, m33[0], m33[1], m33[2]))
                                            elif (m33[0] in m3):
                                                if ("" != m33[1]):
                                                    if ("" != m33[2]):
                                                        try:
                                                            rule_actions_list.append(
                                                                named_tuple_ruleaction(operation, m33[0],
                                                                                       m3["%s" % m33[1]],
                                                                                       m3["%s" % m33[2]]))
                                                        except:
                                                            rule_actions_list.append(
                                                                named_tuple_ruleaction("PROBLEM", "PROBLEM", "PROBLEM",
                                                                                       "PROBLEM"))
                                                            continue
                                                    else:
                                                        rule_actions_list.append(
                                                            named_tuple_ruleaction(operation, m33[0], m3["%s" % m33[1]],
                                                                                   m33[2]))
                                                else:
                                                    rule_actions_list.append(
                                                        named_tuple_ruleaction(operation, m33[0], m33[1], m33[2]))
                                    action_list.append(action(rule_name, rule_index, rule_actions_list))
                            else:
                                rule_actions_list.append(named_tuple_ruleaction("IGNORE", "IGNORE", "IGNORE", "IGNORE"))
                                action_list.append(action(rule_name, rule_index, rule_actions_list))
                            rule_conditions_list = list()
                            if ("conditionsReference" in m2):

                                filter2 = [["not", "contains"], ["not", "equals"], ["not", "startsWith"],
                                           ["not", "endsWith"],
                                           ["startsWith"], ["endsWith"], ["contains"], ["equals"]]
                                filter3 = [["equals"], ["not", "equals"], ["lessOrEqual"], ["less"], ["greater"],
                                           ["greaterOrEqual"]]
                                filter4 = [["matches"]]
                                rule_conditions = ""

                                if ("items" in m2["conditionsReference"]):
                                    rule_conditions_list = list()
                                    for m3 in m2["conditionsReference"]["items"]:
                                        hold1 = 1
                                        name = ""
                                        rules = ""
                                        con1 = []
                                        if ("httpUri" in m3):
                                            con1 = [["path", filter2], ["extension", filter2], ["port", filter3],
                                                    ["host", filter2], ["queryString", filter2],
                                                    ["all", filter2]];
                                            operation = "HTTP_uri"
                                        elif ("cpuUsage" in m3):
                                            con1 = [["last_5mins", filter3], ["last_15secs", filter3],
                                                    ["last_1mins", filter3]];
                                            operation = "CPU_usage"
                                        elif ("httpCookie" in m3):
                                            con1 = [["tmName", filter2]];
                                            operation = "HTTP_cookie"
                                        elif ("httpHeader" in m3):
                                            con1 = [["tmName", filter2]];
                                            operation = "HTTP_header"
                                        elif ("httpHost" in m3):
                                            con1 = [["host", filter2], ["all", filter2], ["port", filter3]];
                                            operation = "HTTP_host"
                                        elif ("httpMethod" in m3):
                                            con1 = [["dummy", filter2]];
                                            operation = "HTTP_method"
                                        elif ("httpReferer" in m3):
                                            con1 = [["path", filter2], ["extension", filter2], ["port", filter3],
                                                    ["host", filter2], ["queryString", filter2],
                                                    ["all", filter2]];
                                            operation = "HTTP_referer"
                                        elif ("httpSetCookie" in m3):
                                            con1 = [["tmName", filter2]];
                                            operation = "HTTP_setcookie"
                                        elif ("httpStatus" in m3):
                                            con1 = [["code", filter3], ["all", filter2], ["text", filter2]];
                                            operation = "HTTP_status"
                                        elif ("httpUserAgent" in m3):
                                            con1 = [["browserType", filter2], ["browserVersion", filter2],
                                                    ["deviceMake", filter2], ["deviceModel", filter2]];
                                            operation = "HTTP_useragent"
                                        elif ("tcp" in m3):
                                            con1 = [["mss", filter3], ["address", filter4], ["port", filter3],
                                                    ["routeDomain", filter3], ["vlanId", filter3],
                                                    ["vlan", filter2]];
                                            operation = "TCP"
                                        else:
                                            rule_conditions += "NOT FOUND;;";
                                            operation = "None"
                                        for m33 in con1:
                                            if (m33[0] in m3 and "values" in m3.keys()):
                                                sssss = []
                                                for m4 in m3["values"]:
                                                    sssss.append(m4)
                                                for m5 in m33[1]:
                                                    string1 = ""
                                                    for m55 in m5:
                                                        if (m55 in m3):
                                                            hold1 = 1
                                                            string1 += m55
                                                        else:
                                                            hold1 = 0
                                                            break
                                                    if (hold1 == 1):
                                                        rule_conditions_list.append(
                                                            named_tuple_rulecondition(operation, m33[0], string1,
                                                                                      sssss))
                                                        break
                                    condition_list.append(condition(rule_name, rule_index, rule_conditions_list))
                            else:
                                rule_conditions_list.append(named_tuple_rulecondition("ALL", "ALL", "ALL", "ALL"))
                                condition_list.append(condition(rule_name, rule_index, rule_conditions_list))
                    dummy_list.append(named_tuple_rule_list(policy["name"], policy["partition"], condition_list,
                                                            action_list))

                # print(rule_list)
        return dummy_list
