from collections import namedtuple



AGILE_AUTHENTICATION_URL = "https://%s:18002/controller/v2/tokens"
AGILE_AUTHENTICATION_DATA = '{"userName":"%s","password":"%s"}'


AGILE_TENANT_URL = "https://%s:18002/controller/dc/v3/tenants"
AGILE_VPC_URL = "https://%s:18002/controller/dc/v3/logicnetwork/networks"
AGILE_SUBNETS_URL = "https://%s:18002/controller/dc/v3/logicnetwork/subnets"
AGILE_LOGICALSW_URL = "https://%s:18002/controller/dc/v3/logicnetwork/switchs"
AGILE_ROUTER_URL = "https://%s:18002/controller/dc/v3/logicnetwork/routers"
AGILE_LOGICALPORTS_URL = "https://%s:18002/controller/dc/v3/logicnetwork/ports"

AGILE_PHYSICALPORTS_URL = "https://%s:18002/acdcn/v3/topoapi/dcntopo/getPorts"
AGILE_DEVICE_URL = "https://%s:18002/acdcn/v3/topoapi/dcntopo/device"




AGILE_PHYSICALPORTS_DATA="""
                {
	                "deviceIdList" : [
		            "%s"
	                            ],
	                "pageSize" : "500",
	                "pageIndex" : "1"
                }"""