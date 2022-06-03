import xml.etree.cElementTree as ET
from collections import namedtuple
import json

class checkpoint_fw_functions:
    @staticmethod
    def get_nats(data):
        named_tuple = namedtuple("NAT", ("NATUID","SourceIP", "DestinationIP","DestinationPort", "TranslatedDestinationIP","TranslatedDestinationPort","TranslatedSourceIP","Status","Creater","Modifier","CreateTime","ModifiedTime"))
        natobjip_list = list()
        natobjservice_list = list()
        dummy_list = list()
        for i in data["objects-dictionary"]:
            #print(i)
            objName, objID, objIP, objPort = "", "", "", ""
            if (i["type"] == "group"):
                objName=i["name"]
                objID=i["uid"]
                objIP=i["name"]
                natobjip_list.append({"objName":objName,"objID":objID,"objIP":objIP})
            if (i["type"] == "host"):
                objName=i["name"]
                objID=i["uid"]
                objIP=i["ipv4-address"]
                natobjip_list.append({"objName":objName,"objID":objID,"objIP":objIP})
            if (i["type"] == "network"):
                objName=i["name"]
                objID=i["uid"]
                objIP=i["subnet4"]+"/"+str(i["mask-length4"])
                natobjip_list.append({"objName":objName,"objID":objID,"objIP":objIP})
            if (i["type"] == "CpmiAnyObject"):
                objName=i["name"]
                objID=i["uid"]
                objIP="any"
                natobjip_list.append({"objName":objName,"objID":objID,"objIP":objIP})
            if (i["type"] == "Global"):
                objName=i["name"]
                objID=i["uid"]
                objIP="Original"
                natobjip_list.append({"objName":objName,"objID":objID,"objIP":objIP})
            if (i["type"] == "service-tcp"):
                objName=i["name"]
                objID=i["uid"]
                objPort=i["port"]
                natobjservice_list.append({"objName":objName,"objID":objID,"objPort":objPort})
            if (i["type"] == "service-group"):
                objName=i["name"]
                objID=i["uid"]
                natobjservice_list.append({"objName":objName,"objID":objID,"objPort":objPort})

        for i in data["rulebase"]:
            for i2 in i["rulebase"]:
                objID, objSrcIP,objSrcIPTranslated,objDstIP,objDstIPTranslated = "", "", "","",""
                objID=i2["uid"]
                status=i2["enabled"]
                creater=i2["meta-info"]["creator"]
                modifier=i2["meta-info"]["last-modifier"]
                createtime=i2["meta-info"]["creation-time"]["iso-8601"]
                modifytime = i2["meta-info"]["last-modify-time"]["iso-8601"]
                try:
                    objSrcIP=[k["objIP"] for k in natobjip_list if k["objID"]==i2["original-source"]]
                    objSrcIPTranslated = [k["objIP"]  for k in natobjip_list if k["objID"] == i2["translated-source"]]
                    objDstIP = [k["objIP"]  for k in natobjip_list if k["objID"] == i2["original-destination"]]
                    objDstIPTranslated = [k["objIP"]  for k in natobjip_list if k["objID"] == i2["translated-destination"]]
                    objDstPort = [k["objPort"]  for k in natobjservice_list if k["objID"] == i2["original-service"]]
                    objDstPortTranslated = [k["objPort"]  for k in natobjservice_list if k["objID"] == i2["translated-service"]]
                    dummy_list.append(named_tuple(objID,objSrcIP,objDstIP,objDstPort,objDstIPTranslated,objDstPortTranslated,objSrcIPTranslated,status,creater,modifier,createtime,modifytime))
                except Exception as e:
                    print(e)
                    continue

        return dummy_list
