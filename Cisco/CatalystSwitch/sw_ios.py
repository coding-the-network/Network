import time
from Network.network import Network
from Network.Cisco.CatalystSwitch.ssh_functions import ssh_functions
from Network.Cisco.CatalystSwitch.snmp_functions import snmp_functions

SSH_PORT = 22


class Catalyst_SW(Network):
    # def __init__(self, ip: str, port: int = SSH_PORT, snmp_community: str = "dddd"):
    #    super().__init__(ip, port, snmp_community)
    class SSH(Network):
        def __init__(self, ip: str, username: str, password: str, port: int = SSH_PORT):
            super().__init__(ip)
            super().get_ssh(username=username, password=password)

        def __get_rest__(self, username="dummy", password="dummy"):
            pass

        def get_uptime(self):
            return ssh_functions.get_uptime(self.ssh_client)

        def get_show_run(self):
            return ssh_functions.get_show_run(self.ssh_client)

        def get_mac_table(self):
            return ssh_functions.get_mac_table(self.ssh_client)

        def get_auth_session(self, auth_session_id="N/A"):
            return ssh_functions.get_auth_session(self.ssh_client,auth_session_id)

        def get_cdp_neighbors(self):
            return ssh_functions.get_cdp_neighbors(self.ssh_client)

        def get_power_inline(self):
            return ssh_functions.get_power_inline(self.ssh_client)

        def get_interface_status(self):
            return ssh_functions.get_interface_status(self.ssh_client)

        def get_vrf(self):
            return ssh_functions.get_vrf(self.ssh_client)

        def get_vlans(self):
            return ssh_functions.get_vlans(self.ssh_client)

        def get_inventory(self):
            return ssh_functions.get_inventory(self.ssh_client)

        def get_interface_stats(self):
            return ssh_functions.get_interface_stats(self.ssh_client)

        def get_portchannels(self):
            return ssh_functions.get_portchannels(self.ssh_client)

        def get_arp(self, vrf_name=""):
            return ssh_functions.get_arp(self.ssh_client, vrf_name)

        def get_ip_interfaces(self, vrf_name=""):
            return ssh_functions.get_ip_interfaces(self.ssh_client, vrf_name)

        def get_routes(self, vrf_name=""):
            return ssh_functions.get_routes(self.ssh_client, vrf_name)

        def get_stp(self, vrf_name=""):
            return ssh_functions.get_stp(self.ssh_client)

        def get_trunks(self, vrf_name=""):
            return ssh_functions.get_trunks(self.ssh_client)

        def get_crashfile(self, vrf_name=""):
            return ssh_functions.get_crashfile(self.ssh_client)

        def get_span(self):
            return ssh_functions.get_span(self.ssh_client)

    class SNMP(Network):
        def __init__(self, ip: str, snmp_community: str = ""):
            super().__init__(ip)
            super().get_snmp(community=snmp_community)

        def __get_rest__(self, username="dummy", password="dummy"):
            pass

        def get_stack_role(self):
            return snmp_functions.get_stack_role(self.ip, self.snmp_community)

        def get_stack_status(self):
            return snmp_functions.get_stack_status(self.ip, self.snmp_community)

        def get_POE(self):
            return snmp_functions.get_POE(self.ip, self.snmp_community)

        def get_interface_info(self):
            sysuptime=self.get_uptime()
            return snmp_functions.get_interface_info(self.ip, self.snmp_community,sysuptime[0].Seconds)

        def get_uptime(self):
            return snmp_functions.get_uptime(self.ip, self.snmp_community)

        def get_temp(self):
            return snmp_functions.get_temp(self.ip, self.snmp_community)

        def get_fan(self):
            return snmp_functions.get_fan(self.ip, self.snmp_community)

        def get_power(self):
            return snmp_functions.get_power(self.ip, self.snmp_community)

        def get_cpu(self):
            return snmp_functions.get_cpu(self.ip, self.snmp_community)

        def get_memory(self):
            return snmp_functions.get_memory(self.ip, self.snmp_community)

        def get_vss(self):
            return snmp_functions.get_vss(self.ip, self.snmp_community)

        def get_cdp(self):
            return snmp_functions.get_cdp(self.ip, self.snmp_community)

        def get_hostname(self):
            return snmp_functions.get_hostname(self.ip, self.snmp_community)


