from Network.network import Network
import requests, json, sys
import threading
from Network.Constants_CP import *
import xml.etree.cElementTree as ET
from collections import namedtuple
import re, time
from Network.Checkpoint.checkpoint_fw_functions import checkpoint_fw_functions as cp_func

class CheckPoint_FW:
    class Rest_Api(Network):
        def __init__(self, ip: str, username: str, password: str , readonly: bool =True):
            self.username = username
            self.password = password
            self.ip= ip
            if(readonly):
                self.headers = {
                    'content-type': "application/json"
                }
            else:
                self.headers = {
                    'content-type': "application/json"
                }
            super().__init__(ip)
            self.Locker = threading.Lock()
            self.thread_list = list()
            self.nat_list=list()
        def __login__(self):
            login_post_data = {"user":self.username , "password":self.password}
            auth_response = json.loads(requests.post(CP_LOGIN_URL % (self.ip), json=login_post_data, verify=False).text)
            self.headers["X-chkp-sid"] = auth_response["sid"]
            print("LOGGED IN")

        def __logout__(self):
            auth_response = requests.post(CP_LOGOUT_URL %(self.ip), json={}, headers=self.headers, verify=False)
            print("LOGGED OUT")

        def __get_data__(self, url: str, returntype: str = "text"):
            try:
                print(self.headers)
                response = requests.get(url=url, headers=self.headers, verify=False)
            except requests.exceptions.ConnectTimeout:
                print("IP is not reachable. You need to call __get_rest__ function "
                      "again to continue")
                return
            if (response.status_code == 200 and returntype=="json"):
                return response.json()
            elif(response.status_code == 200):
                return response.text
            else:
                print("Something went wrong while calling {}".format(url))
                return

        def __post_data__(self, url: str, data: dict, returntype: str = "text"):
            try:
                print(self.headers)
                response = requests.post(url=url, json=data, headers=self.headers, verify=False)
            except requests.exceptions.ConnectTimeout:
                print("IP is not reachable. You need to call __get_rest__ function "
                      "again to continue")
                return
            if (response.status_code == 200 and returntype=="json"):
                return response.json()
            elif(response.status_code == 200):
                return response.text
            else:
                print("Something went wrong while calling {}".format(url))
                return

        def __get_rest__(self, username: str, password: str) -> None:
            pass

        def get_nats(self,package,limit=600):
            nat_data = self.__post_data__(url=CP_NAT_URL % (self.ip),data={"package": package,"limit":limit},returntype="json")
            assert nat_data is not None
            self.nat_list = cp_func.get_nats(nat_data)
            return self.nat_list



