from __future__ import print_function
import json
import requests
import configparser
from requests import api

requests.packages.urllib3.disable_warnings() # Added to avoid warnings in output if proxy

# Parser config file for mandatory variables - global var
config = configparser.ConfigParser()

class API_Object():
    def __init__(self, API_Endpoint, API_Action, API_Token_Required, API_Header = {}, API_Data = {}, API_Params = {}):
        self.API_Endpoint = API_Endpoint
        self.API_Action = API_Action
        self.API_Token_Required = API_Token_Required
        self.API_Header = API_Header
        self.API_Data = API_Data
        self.API_Params = API_Params
    def __repr__(self):
        return "API Object holding all information regarding an API call to Prisma Cloud"
    def __str__(self):
        print("Endpoint      =", self.API_Endpoint)
        print("Action        =", self.API_Action)
        print("Token enabled =", self.API_Token_Required)
        print("Header        =", self.API_Header)
        print("Data          =", self.API_Data)
        print("Params        =", self.API_Params)
        return ""
    def doCall(self):
        print ("Being called for:", self.API_Endpoint)

# Function to parse the config.ini file and see if all is OK.
def validateConfigParser():
    try:
        config.read('config.ini')
    except configparser.Error as e:
        raise SystemExit('!!! Error parsing config.ini file!\n %s' % e)
    return

# Function to execute a call to Prisma Cloud. Returns json body of Prisma Cloud's response.
def doPrismaComputeAPICall (AuthInfo, APIInfo):
    #print (APIInfo)
    full_URL = AuthInfo['URL_base'] + APIInfo.API_Endpoint
    if AuthInfo['authMethod'] == 1 and APIInfo.API_Token_Required == True:
        APIInfo.API_Header['Authorization'] = "Bearer " + AuthInfo['token']
    try:
        response_raw = requests.request(APIInfo.API_Action, full_URL, headers=APIInfo.API_Header, data=APIInfo.API_Data, params=APIInfo.API_Params, verify=AuthInfo['sslverify'])
    except requests.exceptions.RequestException as e:
        raise SystemExit('!!! Error doing API call to Prisma Cloud!\n %s' % e)
    if (response_raw.status_code != 200):
        print("!!! API Call returned not-OK! Exiting script.")
        exit(-1)
    return response_raw.json()

def initializeAuthObjectSource ():
    auth_info = {}
    auth_info['username']  = config.get('SRC_AUTHENTICATION','ACCESS_KEY_ID')
    auth_info['password']  = config.get('SRC_AUTHENTICATION','SECRET_KEY')
    auth_info['sslverify'] = config.get('SRC_SSL_VERIFY','ENABLE_VERIFY')
    auth_info['URL_base']  = config.get('SRC_URL','URL')
    auth_info['authMethod'] = 0
    auth_info['sslverify'] = (auth_info['sslverify'].lower() != "false" )
    if (not auth_info['sslverify']):
        print ("--- WARNING: Not using SSL verification as configured in config.ini file.")
    return auth_info

def initializeAuthObjectDestination ():
    auth_info = {}
    auth_info['username']  = config.get('DST_AUTHENTICATION','ACCESS_KEY_ID')
    auth_info['password']  = config.get('DST_AUTHENTICATION','SECRET_KEY')
    auth_info['sslverify'] = config.get('DST_SSL_VERIFY','ENABLE_VERIFY')
    auth_info['URL_base']  = config.get('DST_URL','URL')
    auth_info['authMethod'] = 0
    auth_info['sslverify'] = (auth_info['sslverify'].lower() != "false" )
    if (not auth_info['sslverify']):
        print ("--- WARNING: Not using SSL verification as configured in config.ini file.")
    return auth_info

# Function to authenticate to Prisma Cloud. Returns token as obtained.
def authenticatePrismaCloudCompute (Target):
    auth = {}
    if (Target == "SRC" ): 
        auth_info = initializeAuthObjectSource()
    else:
        if (Target == "DST") : 
            auth_info = initializeAuthObjectDestination()
    auth['username'] = auth_info['username']
    auth['password'] = auth_info['password']
    auth_body = json.dumps(auth)
    API_Info = API_Object("/api/v21.08/authenticate", "POST", False, {'Content-Type': 'application/json'}, API_Data=auth_body)
    print("\n--- Authenticating to Prisma Cloud via provided token.")
    response = doPrismaComputeAPICall(auth_info, API_Info)
    print (f"-   Successfully authenticated to Prisma Cloud", Target, "with SSL verification set to:", auth_info['sslverify'])
    auth_info['token'] = response['token']
    auth_info['authMethod'] = 1 # Use token for authentication from here on
    return auth_info

def fetchPrismaComputeContainerPolicy(authInfo):
    API_Info = API_Object("/api/v21.08/policies/runtime/container", "GET", True)
    response = doPrismaComputeAPICall(authInfo, API_Info)
    return response

def fetchPrismaComputeCustomPolicy(authInfo):
    API_Info = API_Object("/api/v1/custom-rules", "GET", True, API_Params="project=Central+Console")
    response = doPrismaComputeAPICall(authInfo, API_Info)
    return response

# Example CUSTOM RULE
#{ 'name': 'Test rule', 
#  '_id': 34, 
#  'type': 'processes', 
#  'script': 'proc.name = "usermod" or proc.cmdline contains "usermod"\nproc.name = "test"', 
#  'description': '', 
#  'message': 'Halp', 
#  'owner': 'edoezie_paloaltonetworks_com', 
#  'modified': 1636372869 }

def createPrismaComputeCustomPolicy(authInfo, ID):
    API_Info = API_Object("/api/v1/custom-rules/"+ID, "PUT", True, API_Params="project=Central+Console")
    response = doPrismaComputeAPICall(authInfo, API_Info)
    return response

# Request URL: /api/v1/tags?project=Central+Console
# GET. Response:
# [{"name":"Ignored","color":"#FFEDF2","vulns":[{"id":"CVE-2021-3711","packageName":"openssl"}]}
# ,{"name":"In progress","color":"#F1FFC5"}
# ,{"name":"For review","color":"#D8ECC8","vulns":[{"id":"CVE-2017-12424","packageName":"shadow"}]}
# ,{"name":"DevOps notes","color":"#C6C7DA"}]
def listCVETags(authInfo):
    API_Info = API_Object("/api/v1/tags", "GET", True, API_Params="project=Central+Console")
    response = doPrismaComputeAPICall(authInfo, API_Info)
    return response

# Request URL: /api/v1/tags/For%20review/vuln?project=Central+Console
# Payload: {"id":"CVE-2017-12424","packageName":"shadow"}
def tagCVE (authInfo, ID, State):
    API_Info = API_Object("/api/v1/custom-rules/"+ID, "PUT", True, API_Params="project=Central+Console")
    response = doPrismaComputeAPICall(authInfo, API_Info)
    return response

def cloneObject(sourceObject, destinationAuthInfo):
    print ("Cloning", sourceObject, "into", destinationAuthInfo['URL_base'])
    return

def compareObjects (iterableOne, iterableTwo, fieldList):
    missingItems = []
    totalFields = len(fieldList)
    for itemOne in iterableOne:
        foundMatch = False
        for itemTwo in iterableTwo:
            fieldsMatched = 0
            for field in fieldList:
                if itemOne[field] == itemTwo[field]:
                    fieldsMatched += 1
            if (fieldsMatched == totalFields):
                foundMatch = True
                #print ("Matched: ", itemOne['name'])
                break
        if (not foundMatch):
            #print ("Missing this item!", itemOne['name'])
            missingItems.append(itemOne)
    return missingItems

def main ():
    auth_info_src = {}
    auth_info_dst = {}
    validateConfigParser()

    auth_info_src = authenticatePrismaCloudCompute("SRC")
    auth_info_dst = authenticatePrismaCloudCompute("DST")
    source_policies = fetchPrismaComputeCustomPolicy (auth_info_src)
    dest_policies = fetchPrismaComputeCustomPolicy (auth_info_dst)
    
    itemsToClone = compareObjects(source_policies, dest_policies, ['name', '_id'])
    print ("- Policies to CLONE: ")
    for item in itemsToClone:
        print (item['name'])
    #    cloneObject(item, auth_info_dst)
    
    src_cve_tags = listCVETags(auth_info_src)
    dst_cve_tags = listCVETags(auth_info_dst)
    itemsToClone = compareObjects(src_cve_tags, dst_cve_tags, ['name'])
    print ("- Tags to CLONE: ")
    for item in itemsToClone:
        print (item['name'])
    #    cloneObject(item, auth_info_dst)

if __name__ == "__main__":
    main()