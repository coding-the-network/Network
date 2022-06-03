from collections import namedtuple

F5_AUTHENTICATION_URL = "https://%s/mgmt/shared/authn/login"
F5_AUTHENTICATION_DATA = "{\"username\":%s,\"password\":%s,\"loginProviderName\":\"tmos\"}"

F5_NODE_URL_INIT = "https://%s/mgmt/tm/ltm/node?$skip=0&$top=1&expandSubcollections=true"
F5_NODE_URL_CONTINUE = "https://%s/mgmt/tm/ltm/node?$skip=%s&$top=500&expandSubcollections=true"


F5_POOL_URL_INIT = "https://%s/mgmt/tm/ltm/pool?$skip=0&$top=1&expandSubcollections=true"
F5_POOL_URL_CONTINUE = "https://%s/mgmt/tm/ltm/pool?$skip=%s&$top=500&expandSubcollections=true"

F5_VS_URL_INIT = "https://%s/mgmt/tm/ltm/virtual?$skip=0&$top=1&expandSubcollections=true"
F5_VS_URL_CONTINUE = "https://%s/mgmt/tm/ltm/virtual?$skip=%s&$top=500&expandSubcollections=true"

F5_POLICY_URL_INIT = "https://%s/mgmt/tm/ltm/policy?$skip=0&$top=1&expandSubcollections=true"
F5_POLICY_URL_CONTINUE = "https://%s/mgmt/tm/ltm/policy?$skip=%s&$top=500&expandSubcollections=true"

F5_POOLSTATS_URL_INIT = "https://%s/mgmt/tm/ltm/pool/stats?$skip=0&$top=1&expandSubcollections=true"
F5_POOLSTATS_URL_CONTINUE = "https://%s/mgmt/tm/ltm/pool/stats?$skip=%s&$top=500&expandSubcollections=true"

F5_IRULE_URL_INIT = "https://%s/mgmt/tm/ltm/rule?$skip=0&$top=1&expandSubcollections=true"
F5_IRULE_URL_CONTINUE = "https://%s/mgmt/tm/ltm/rule?$skip=%s&$top=500&expandSubcollections=true"

F5_VIRTUALSTATS_URL_INIT = "https://%s/mgmt/tm/ltm/virtual/stats?$skip=0&$top=1&expandSubcollections=true"
F5_VIRTUALSTATS_URL_CONTINUE = "https://%s/mgmt/tm/ltm/virtual/stats?$skip=%s&$top=500&expandSubcollections=true"
F5_VIRTUALPROFILESTATS_URL = "https://%s/mgmt/tm/ltm/virtual/~%s~%s/profiles/stats"

F5_CLIENTSSL_URL_INIT = "https://%s/mgmt/tm/ltm/profile/client-ssl?$skip=0&$top=1&expandSubcollections=true"
F5_CLIENTSSL_URL_CONTINUE = "https://%s/mgmt/tm/ltm/profile/client-ssl?$skip=%s&$top=500&expandSubcollections=true"

F5_CLIENTSSLSTATS_URL_INIT = "https://%s/mgmt/tm/ltm/profile/client-ssl/stats?$skip=0&$top=1&expandSubcollections=true"
F5_CLIENTSSLSTATS_URL_CONTINUE = "https://%s/mgmt/tm/ltm/profile/client-ssl/stats?$skip=%s&$top=500&expandSubcollections=true"

F5_SERVERSSL_URL_INIT = "https://%s/mgmt/tm/ltm/profile/server-ssl?$skip=0&$top=1&expandSubcollections=true"
F5_SERVERSSL_URL_CONTINUE = "https://%s/mgmt/tm/ltm/profile/server-ssl?$skip=%s&$top=500&expandSubcollections=true"

F5_WIDEIP_URL_INIT = "https://%s/mgmt/tm/gtm/wideip/a?$skip=0&$top=1&expandSubcollections=true"
F5_WIDEIP_URL_CONTINUE = "https://%s/mgmt/tm/gtm/wideip/a?$skip=%s&$top=500&expandSubcollections=true"

F5_GTMSERVERS_URL_INIT = "https://%s/mgmt/tm/gtm/server?$skip=0&$top=1&expandSubcollections=true"
F5_GTMSERVERS_URL_CONTINUE = "https://%s/mgmt/tm/gtm/server?$skip=%s&$top=500&expandSubcollections=true"

F5_GTMPOOLS_URL_INIT = "https://%s/mgmt/tm/gtm/pool/a/?$skip=0&$top=1&expandSubcollections=true"
F5_GTMPOOLS_URL_CONTINUE = "https://%s/mgmt/tm/gtm/pool/a/?$skip=%s&$top=500&expandSubcollections=true"

F5_CONFIGSYNC_URL = "https://%s/mgmt/tm/cm/device-group/~Common~%s/stats"

F5_HTTPPROFILE_URL_INIT = "https://%s/mgmt/tm/ltm/profile/http?$skip=0&$top=1&expandSubcollections=true"
F5_HTTPPROFILE_URL_CONTINUE = "https://%s/mgmt/tm/ltm/profile/http?$skip=%s&$top=500&expandSubcollections=true"

F5_TCPPROFILE_URL_INIT = "https://%s/mgmt/tm/ltm/profile/tcp?$skip=0&$top=1&expandSubcollections=true"
F5_TCPPROFILE_URL_CONTINUE = "https://%s/mgmt/tm/ltm/profile/tcp?$skip=%s&$top=500&expandSubcollections=true"

F5_UDPPROFILE_URL_INIT = "https://%s/mgmt/tm/ltm/profile/udp?$skip=0&$top=1&expandSubcollections=true"
F5_UDPPROFILE_URL_CONTINUE = "https://%s/mgmt/tm/ltm/profile/udp?$skip=%s&$top=500&expandSubcollections=true"

F5_FASTL4PROFILE_URL_INIT = "https://%s/mgmt/tm/ltm/profile/fastl4?$skip=0&$top=1&expandSubcollections=true"
F5_FASTL4PROFILE_URL_CONTINUE = "https://%s/mgmt/tm/ltm/profile/fastl4?$skip=%s&$top=500&expandSubcollections=true"

F5_COOKIEPERSIST_URL_INIT = "https://%s/mgmt/tm/ltm/persistence/cookie?$skip=0&$top=1&expandSubcollections=true"
F5_COOKIEPERSIST_URL_CONTINUE = "https://%s/mgmt/tm/ltm/persistence/cookie?$skip=%s&$top=500&expandSubcollections=true"
F5_SRCPERSIST_URL_INIT = "https://%s/mgmt/tm/ltm/persistence/source-addr?$skip=0&$top=1&expandSubcollections=true"
F5_SRCPERSIST_URL_CONTINUE = "https://%s/mgmt/tm/ltm/persistence/source-addr?$skip=%s&$top=500&expandSubcollections=true"
F5_UNIVERSALPERSIST_URL_INIT = "https://%s/mgmt/tm/ltm/persistence/universal?$skip=0&$top=1&expandSubcollections=true"
F5_UNIVERSALPERSIST_URL_CONTINUE = "https://%s/mgmt/tm/ltm/persistence/universal?$skip=%s&$top=500&expandSubcollections=true"
F5_SSLPERSIST_URL_INIT = "https://%s/mgmt/tm/ltm/persistence/ssl?$skip=0&$top=1&expandSubcollections=true"
F5_SSLPERSIST_URL_CONTINUE = "https://%s/mgmt/tm/ltm/persistence/ssl?$skip=%s&$top=500&expandSubcollections=true"

F5_CERTFILES_URL_INIT = "https://%s/mgmt/tm/sys/file/ssl-cert?$skip=0&$top=1&expandSubcollections=true"
F5_CERTFILES_URL_CONTINUE = "https://%s/mgmt/tm/sys/file/ssl-cert?$skip=%s&$top=500&expandSubcollections=true"

F5_ASM_URL_INIT = "https://%s/mgmt/tm/asm/policies?$skip=0&$top=1&expandSubcollections=true"
F5_ASM_URL_CONTINUE = "https://%s/mgmt/tm/asm/policies?$skip=%s&$top=500&expandSubcollections=true"

F5_ASM_ASSIGNED_SIG_URL_INIT = "https://%s/mgmt/tm/asm/policies/%s/signatures?$skip=0&$top=1&expandSubcollections=true"
F5_ASM_ASSIGNED_SIG_URL_CONTINUE = "https://%s/mgmt/tm/asm/policies/%s/signatures?$skip=%s&$top=1000&expandSubcollections=true"

F5_ASM_BLOCKING_SETTINGS_VIOLATIONS = "https://%s/mgmt/tm/asm/policies/%s/blocking-settings/violations?$expandSubcollections=true"
F5_ASM_BLOCKING_SETTINGS_EVASIONS = "https://%s/mgmt/tm/asm/policies/%s/blocking-settings/evasions?$expandSubcollections=true"
F5_ASM_BLOCKING_SETTINGS_HTTP = "https://%s/mgmt/tm/asm/policies/%s/blocking-settings/http-protocols?$expandSubcollections=true"

F5_ASM_SIG_URL_INIT = "https://%s/mgmt/tm/asm/signatures?$skip=0&$top=1&expandSubcollections=true"
F5_ASM_SIG_URL_CONTINUE = "https://%s/mgmt/tm/asm/signatures?$skip=%s&$top=1000&expandSubcollections=true"