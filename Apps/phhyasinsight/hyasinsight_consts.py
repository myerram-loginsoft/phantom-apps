import re

# Indicator Types
DOMAIN = "domain"
IP = "ip"
IPV4 = "ipv4"
EMAIL = "email"
PHONE = "phone"
IPV6 = "ipv6"
SHA256 = "sha256"

# Endpoints
HYAS_BASE_URL = "https://apps.hyas.com/api/ext/"
PASSIVEDNS = "passivedns"
DYNAMICDNS = "dynamicdns"
PASSIVEHASH = "passivehash"
SINKHOLE = "sinkhole"
C2ATTRIBUTION = "c2attribution"
DEVICEGEO = "device_geo"
SSL = "ssl_certificate"
WHOIS = "whois"
CURRENT_WHOIS_BASE_URL = 'https://api.hyas.com'
CURRENT_WHOIS = '/whois/v1'
CURRENT_WHOIS_NAME = 'current_whois'
SSL_CERTS = "ssl_certs"
ITEMS = "items"


# test Endpoints
HYAS_TEST_PASSIVEHASH_ENDPOINT = "passivehash"
HYAS_TEST_PAYLOAD_KEY = "domain"
HYAS_TEST_PAYLOAD_VALUE = "google.com"

# Request Data
HYAS_JSON_APIKEY = "apikey"
HYAS_JSON_APIKEY_HEADER = "x-api-key"

# regex
IP_REG = (
    r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.)"
    "{3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
)
IPV6_REG = r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"

DOMAIN_REG = re.compile(
    r"^(?:[a-zA-Z0-9]"  # First character of the domain
    r"(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)"  # Sub domain + hostname
    r"+[A-Za-z0-9][A-Za-z0-9-_]{0,61}"  # First 61 characters of the gTLD
    r"[A-Za-z]$"  # Last character of the gTLD
)
EMAIL_REG = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}"
PHONE_REG = r"^\+?[1-9]\d{1,14}$"
SHA_REG = r"[A-Fa-f0-9]{64}"
URL_REG = (
    r"((http|https)://)(www.)?[a-zA-Z0-9@:%._\\+~#?&//=]{2,256}"
    "\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)"
)
IOC_NAME = {
    "ip": IP_REG,
    "ipv4": IP_REG,
    "ipv6": IPV6_REG,
    "domain": DOMAIN_REG,
    "email": EMAIL_REG,
    "phone": PHONE_REG,
    "sha256": SHA_REG,
}

# status messages
HYAS_ERR_MSG_INVALID_INDICATOR_VALUE = "Invalid Indicator value"
HYAS_TEST_CONN_PASSED="Test Connectivity Passed"
HYAS_TEST_CONN_FAILED="Test Connectivity Failed."

HYAS_ERR_ASSET_API_KEY_="API Key asset setting not configured! Please validate asset configuration and save"
HYAS_ERR_CODE_MSG = "Error code unavailable"
HYAS_ERR_MSG_UNAVAILABLE = (
    "Error message unavailable."
    " Please check the asset configuration "
    "and|or action parameters"
)
HYAS_PARSE_ERR_MSG = (
    "Unable to parse the error message. Please check the asset "
    "configuration and|or action parameters"
)
HYAS_HTML_ERR_MSG = "Please check the asset configuration and|or action parameters"
HYAS_ASSET_ERR_MSG = "Please check the asset configuration and|or action parameters"

# Jsons used in params, result, summary etc.
ACTION_ID_PARAM = {
    "lookup_c2_domain": "domain",
    "lookup__c2__email": "email",
    "lookup_c2_ip": "ip",
    "lookup_c2_sha256": "sha256",
    "lookup_whois_domain": "domain",
    "lookup_device_geo_ipv4": "ipv4",
    "lookup_device_geo_ipv6": "ipv6",
    "lookup_whois_email": "email",
    "lookup_whois_phone": "phone",
    "lookup_dynamicdns_email": "email",
    "lookup_dynamicdns_ip": "ip",
    "lookup_sinkhole_ip": "ip",
    "lookup_passivehash_ip": "ip",
    "lookup_passivehash_domain": "domain",
    "lookup_passivedns_ip": "ip",
    "lookup_passivedns_domain": "domain",
    "lookup_ssl_certificate_ip": "ip",
    "lookup_current_whois_domain": "domain"

}

# ACTION_ID_PARAM = {
#     "lookup_c2_domain": "c2_domain",
#     "lookup__c2__email": "c2_email",
#     "lookup_c2_ip": "c2_ip",
#     "lookup_c2_sha256": "c2_sha256",
#     "lookup_whois_domain": "whois_domain",
#     "lookup_device_geo_ipv4": "devicegeo_ipv4",
#     "lookup_device_geo_ipv6": "devicegeo_ipv6",
#     "lookup_whois_email": "whois_email",
#     "lookup_whois_phone": "whois_phone",
#     "lookup_dynamicdns_email": "dynamicdns_email",
#     "lookup_dynamicdns_ip": "dynamicdns_ip",
#     "lookup_sinkhole_ip": "sinkhole_ip",
#     "lookup_passivehash_ip": "passivehash_ip",
#     "lookup_passivehash_domain": "passivehash_domain",
#     "lookup_passivedns_ip": "passivedns_ip",
#     "lookup_passivedns_domain": "passivedns_domain",
#     "lookup_ssl_certificate_ip": "sslcertificate_ip",
#     "lookup_current_whois_domain": "currentwhois_domain"
#
# }

IOC_DETAILS = {
    "lookup_c2_domain": {"endpoint": C2ATTRIBUTION, "indicator_type": DOMAIN},
    "lookup__c2__email": {"endpoint": C2ATTRIBUTION, "indicator_type": EMAIL},
    "lookup_c2_ip": {"endpoint": C2ATTRIBUTION, "indicator_type": IP},
    "lookup_c2_sha256": {"endpoint": C2ATTRIBUTION, "indicator_type": SHA256},
    "lookup_whois_domain": {"endpoint": WHOIS, "indicator_type": DOMAIN},
    "lookup_whois_email": {"endpoint": WHOIS, "indicator_type": EMAIL},
    "lookup_whois_phone": {"endpoint": WHOIS, "indicator_type": PHONE},
    "lookup_device_geo_ipv4": {"endpoint": DEVICEGEO, "indicator_type": IPV4},
    "lookup_device_geo_ipv6": {"endpoint": DEVICEGEO, "indicator_type": IPV6},
    "lookup_dynamicdns_email": {"endpoint": DYNAMICDNS, "indicator_type": EMAIL},
    "lookup_dynamicdns_ip": {"endpoint": DYNAMICDNS, "indicator_type": IP},
    "lookup_sinkhole_ip": {"endpoint": SINKHOLE, "indicator_type": IPV4},
    "lookup_passivehash_ip": {"endpoint": PASSIVEHASH, "indicator_type": IPV4},
    "lookup_passivehash_domain": {"endpoint": PASSIVEHASH, "indicator_type": DOMAIN},
    "lookup_passivedns_domain": {"endpoint": PASSIVEDNS, "indicator_type": DOMAIN},
    "lookup_passivedns_ip": {"endpoint": PASSIVEDNS, "indicator_type": IPV4},
    "lookup_ssl_certificate_ip": {"endpoint": SSL, "indicator_type": IP},
    "lookup_current_whois_domain": {"endpoint": CURRENT_WHOIS, "indicator_type": DOMAIN}
}


# IOC_DETAILS = {
#     "c2_domain": {"endpoint": C2ATTRIBUTION, "indicator_type": DOMAIN},
#     "c2_email": {"endpoint": C2ATTRIBUTION, "indicator_type": EMAIL},
#     "c2_ip": {"endpoint": C2ATTRIBUTION, "indicator_type": IP},
#     "c2_sha256": {"endpoint": C2ATTRIBUTION, "indicator_type": SHA256},
#     "whois_domain": {"endpoint": WHOIS, "indicator_type": DOMAIN},
#     "whois_email": {"endpoint": WHOIS, "indicator_type": EMAIL},
#     "whois_phone": {"endpoint": WHOIS, "indicator_type": PHONE},
#     "devicegeo_ipv4": {"endpoint": DEVICEGEO, "indicator_type": IPV4},
#     "devicegeo_ipv6": {"endpoint": DEVICEGEO, "indicator_type": IPV6},
#     "dynamicdns_email": {"endpoint": DYNAMICDNS, "indicator_type": EMAIL},
#     "dynamicdns_ip": {"endpoint": DYNAMICDNS, "indicator_type": IP},
#     "sinkhole_ip": {"endpoint": SINKHOLE, "indicator_type": IPV4},
#     "passivehash_ip": {"endpoint": PASSIVEHASH, "indicator_type": IPV4},
#     "passivehash_domain": {"endpoint": PASSIVEHASH, "indicator_type": DOMAIN},
#     "passivedns_domain": {"endpoint": PASSIVEDNS, "indicator_type": DOMAIN},
#     "passivedns_ip": {"endpoint": PASSIVEDNS, "indicator_type": IPV4},
#     "sslcertificate_ip": {"endpoint": SSL, "indicator_type": IP},
#     "currentwhois_domain": {"endpoint": CURRENT_WHOIS, "indicator_type": DOMAIN}
# }

ACTION_ID=["lookup_c2_domain",
            "lookup__c2__email",
            "lookup_c2_ip",
            "lookup_c2_sha256",
            "lookup_whois_domain",
            "lookup_device_geo_ipv4",
            "lookup_device_geo_ipv6",
            "lookup_whois_email",
            "lookup_whois_phone",
            "lookup_dynamicdns_email",
            "lookup_dynamicdns_ip",
            "lookup_sinkhole_ip",
            "lookup_passivehash_ip",
            "lookup_passivehash_domain",
            "lookup_passivedns_ip",
            "lookup_passivedns_domain",
            "lookup_ssl_certificate_ip",
            "lookup_current_whois_domain"]