'''
    create new XDR incident from an incident-summary.json file located into the ./incident-summary subfolder
    create :
    - Incident
    - Incidents Sightings
    - Sightings Observables
    - Sighting targets
    - Sighting observable to target relationships
    - Sighting to Incident relationships
    - Indicators
    - Sighting to Indicator relationships
'''
import json, sys
from datetime import datetime, date, timedelta
import time
import hashlib
from crayons import *
import json
import sys
import requests
import os
import string
import random

# Get global variable from config.py
incident_summary={}
indicator_map={} # map indicator id between old tenant and new tenant
method="config.txt"  # for futur use :  must be either config.txt or ../key  or database  or vault or environment variable
host = ""
host_for_token=""
ctr_client_id=""
ctr_client_password=""
SOURCE_FOR_EVERYTHING ="XDR Demo" # in order to identify easily everyobjects we create into the destination tenant ( if we want to clean them )

# Get the current date/time
dateTime = datetime.now()

def parse_config(text_content):
    text_lines=text_content.split('\n')
    conf_result=['','','','','','','']
    for line in text_lines:
        print(green(line,bold=True))
        if 'ctr_client_id' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[0]=line.split('=')[1]
                conf_result[0]=conf_result[0].replace('"','')
                conf_result[0]=conf_result[0].replace("'","")
            else:
                conf_result[0]=""
        elif 'ctr_client_password' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[1]=line.split('=')[1]
                conf_result[1]=conf_result[1].replace('"','')
                conf_result[1]=conf_result[1].replace("'","")
            else:
                conf_result[1]=""        
        elif '.eu.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.eu.amp.cisco.com" 
            conf_result[6]="https://visibility.eu.amp.cisco.com"
        elif '.intel.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.amp.cisco.com"   
            conf_result[6]="https://visibility.amp.cisco.com"
        elif '.apjc.amp.cisco.com' in line:
            conf_result[2]="https://private.intel.apjc.amp.cisco.com"
            conf_result[6]="https://visibility.apjc.amp.cisco.com"
        elif 'SecureX_Webhook_url' in line:
            words=line.split('=')
            if len(words)==2:        
                print(yellow(words))        
                conf_result[3]=words[1]
                conf_result[3]=conf_result[3].replace('"','')
                conf_result[3]=conf_result[3].replace("'","")                
            else:
                conf_result[3]=""
        elif 'webex_bot_token' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[5]=line.split('=')[1]
                conf_result[5]=conf_result[5].replace('"','')
                conf_result[5]=conf_result[5].replace("'","")
            else:
                conf_result[5]=""        
        elif 'webex_room_id' in line:
            words=line.split('=')
            if len(words)==2:
                conf_result[4]=line.split('=')[1]
                conf_result[4]=conf_result[4].replace('"','')
                conf_result[4]=conf_result[4].replace("'","")
            else:
                conf_result[4]=""        
    print(yellow(conf_result))
    return conf_result

def read_api_keys(service):   
    # read API credentials from an external file on this laptop ( API keys are not shared with the flask application )
    if service=="ctr":
        if ctr_client_id=='paste_CTR_client_ID_here':
            with open('../keys/ctr_api_keys.txt') as creds:
                text=creds.read()
                cles=text.split('\n')
                client_id=cles[0].split('=')[1]
                client_password=cles[1].split('=')[1]
                #access_token = get_token()
                #print(access_token) 
        else:
            client_id=ctr_client_id
            client_password=ctr_client_password
        return(client_id,client_password)

def get_ctr_token(host_for_token,ctr_client_id,ctr_client_password):
    print(yellow('Asking for new CTR token',bold=True))
    url = f'{host_for_token}/iroh/oauth2/token'
    print()
    print(url)
    print()    
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    print()
    print('ctr_client_id : ',green(ctr_client_id,bold=True))
    print('ctr_client_password : ',green(ctr_client_password,bold=True))
    response = requests.post(url, headers=headers, auth=(ctr_client_id, ctr_client_password), data=payload)
    #print(response.json())
    reponse_list=response.text.split('","')
    token=reponse_list[0].split('":"')
    print('token = ',token[1])
    if 'invalid_client' in token[1]:
        print(red('Error = bad client_id or client_password !',bold=True))
        return 0
    else:        
        fa = open("ctr_token.txt", "w")
        fa.write(token[1])
        fa.close()
        return (token[1])
    
def get(host,access_token,url,offset,limit):    
    # just for checking that the token is valid
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    url = f"{host}{url}?source=XDR Demo&limit={limit}&offset={offset}"
    response = requests.get(url, headers=headers)
    return response
    
def check_ctr_token(host,host_for_token,ctr_client_id,ctr_client_password):
    '''
        check current ctr and if this one is not valid then generate a new one
    '''
    path = './ctr_token.txt'
    if os.path.isfile(path):
        fa = open("ctr_token.txt", "r")
        access_token = fa.readline()
        fa.close() 
    else:
        access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
    url = "/ctia/incident/search"
    offset=0
    limit=1
    response = get(host,access_token,url,offset,limit)
    payload = json.dumps(response.json(),indent=4,sort_keys=True, separators=(',', ': '))
    print(payload) 
    if response.status_code==401:
        print("Asking for a Token") 
        access_token=get_ctr_token(host_for_token,ctr_client_id,ctr_client_password)
    elif response.status_code!=200:
        print(red(response.status_code,bold=True)) 
        print()         
        print(red("Error !",bold=True))    
        print(response.json())  
        print()        
    else:
        print("Ok Token Is valid : ",green(response.status_code,bold=True))                 
        print()             
    return(access_token)

def read_incident_summary():
    file='./incident_summary/incident-summary.json'
    with open(file,'r') as file:
        text_data=file.read()
        json_data=json.loads(text_data)
        #print(cyan(json_data,bold=True))     
        #print()
    return(json_data)
    
def create_incident_xid():
    hash_strings = [ "some_string to put here" + str(time.time())]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    incident_xid = 'transient:sxo-incident-' + hash_value
    print("  - Incident External ID : ",cyan(incident_xid,bold=True))
    return incident_xid

def create_incident_json():
    print(yellow("- > Step 1.1 create_incident_xid",bold=True))
    # Build the incident objects
    #xid="transient:"+create_incident_xid() DEBUG PATRIKC
    xid=create_incident_xid()
    print(yellow("- > Step 1.2 create_incident_jSON",bold=True))
    incident_object = {}
    incident_object["description"] = incident_summary[0]['description']
    incident_object["schema_version"] = "1.3.9"
    incident_object["type"] = "incident"
    incident_object["source"] = SOURCE_FOR_EVERYTHING
    incident_object["short_description"] = incident_summary[0]['title']
    incident_object["title"] = incident_summary[0]['title']
    incident_object["incident_time"] = { "discovered": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ"), "opened": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
    incident_object["status"] = "New"
    incident_object["tlp"] = incident_summary[0]['tlp']
    incident_object["confidence"] = incident_summary[0]['confidence']
    incident_object["severity"] = incident_summary[0]['severity']
    incident_object["id"] = xid
    incident_object["techniques"] = incident_summary[0]['techniques']
    incident_object["tactics"] = incident_summary[0]['tactics']
    incident_object["categories"]:[categories[3]]
    incident_object["discovery_method"]:discover_method[2]
    incident_object["promotion_method"]=incident_summary[0]['promotion_method']   
    incident_object["scores"]={}
    incident_object["scores"]["asset"]=incident_summary[0]["scores"]["asset"]
    incident_object["scores"]["ttp"]=incident_summary[0]["scores"]["ttp"]
    incident_object["scores"]["global"]=incident_summary[0]["scores"]["global"]   
    incident_json = json.dumps(incident_object)
    payload = json.dumps(incident_object,indent=4,sort_keys=True, separators=(',', ': '))
    #print(response.json())     
    print()
    print(' Incidents JSON :\n',cyan(payload,bold=True))
    return(incident_json,xid)
    
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return (''.join(random.choice(chars) for _ in range(size)))

def create_sighting_xid(sighting_title):
    d = datetime.now()
    current_time = d.strftime("%d/%m/%Y %H:%M:%S")
    nombre=random.randint(1, 10)
    texte=sighting_title+id_generator(nombre, "6793YUIO")
    hash_strings = [texte, current_time]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    sighting_xid = "sxo-sighting-" + hash_value
    print("  - Sighting External ID : ",cyan(sighting_xid,bold=True))
    return sighting_xid
    
def create_indicator_xid(indicator_title):
    d = datetime.now()
    current_time = d.strftime("%d/%m/%Y %H:%M:%S")
    nombre=random.randint(1, 10)
    texte=sighting_title+id_generator(nombre, "1234YUZO")
    hash_strings = [indicator_title, current_time]
    hash_input = "|".join(hash_strings)
    hash_value = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    sighting_xid = "sxo-indicator-" + hash_value
    print("  - Indicator External ID : ",cyan(indicator_xid,bold=True))
    return indicator_xid

def today():
    d = date.today()
    return d.strftime("%Y-%m-%d")
    

def create_sighting_json(xid,this_sighting):
    #start_date = dateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
    sighting_obj_json = {}
    sighting_obj_json["confidence"] = this_sighting["confidence"]
    print("   - Get Observables and add them into sighting definition")
    if 'observables' in this_sighting.keys():
        sighting_obj_json["observables"] = this_sighting["observables"]
    print("   - Get Targets and add them into sighting definition")
    if 'targets' in this_sighting.keys():
        sighting_obj_json["targets"] = this_sighting["targets"]
    sighting_obj_json["external_ids"] = [xid]
    sighting_obj_json["id"] ="transient:"+xid 
    sighting_obj_json["description"] = this_sighting["description"]
    sighting_obj_json["short_description"] = this_sighting["short_description"] 
    sighting_obj_json["title"] = this_sighting["title"]
    sighting_obj_json["source"] = this_sighting["source"].replace(' (cisco-jefflen)','')
    sighting_obj_json["type"] = "sighting"
    # SIGHTING DATE HERE
    #sighting_obj_json["observed_time"] = {"start_time": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ") }
    sighting_obj_json["observed_time"] = this_sighting["observed_time"]
    sighting_obj_json["tlp"] = this_sighting["tlp"]
    sighting_obj_json["severity"] = this_sighting["severity"]
    if 'sensor' in this_sighting.keys():
        sighting_obj_json['sensor'] = this_sighting['sensor']
    if 'resolution' in this_sighting.keys():
        sighting_obj_json['resolution'] = this_sighting['resolution']
    print("   - Get sighting observable relations and add them into sighting definition")
    relation_list=[]
    if 'relations' in this_sighting.keys():
        for relation in this_sighting['relations']:
            print('---------')
            if relation['relation']!='member_of' and relation['relation']!='sighting_of':
                print(relation)
                relation_list.append(relation)
            #a=input('STOP')
        sighting_obj_json["relations"]=relation_list
    print()
    print(' Sightings JSON :\n',cyan(sighting_obj_json,bold=True))
    return json.dumps(sighting_obj_json)   
    
def create_relationship_object(source_xid, target_xid, relationship_xid, relationship_type):
    relationship_json = {}
    relationship_json["external_ids"] = ["transient:"+relationship_xid]
    relationship_json["source_ref"] = source_xid
    relationship_json["target_ref"] = target_xid
    relationship_json["source"] = SOURCE_FOR_EVERYTHING
    relationship_json["relationship_type"] = relationship_type
    relationship_json["type"] = "relationship"
    relationship_json["id"] = "transient:"+relationship_xid
    print(' relationships :\n',cyan(relationship_json,bold=True))
    return json.dumps(relationship_json)

def generate_relationship_xid(source_xid, target_xid):
    hash_value = hashlib.sha1((source_xid + target_xid).encode('utf-8'))
    hash_value = hash_value.hexdigest()
    relationship_xid = "sxo-relationship-" + hash_value
    print(' Relationships External ID :\n',cyan(relationship_xid,bold=True))
    return relationship_xid

def create_incident_indicators():
    indicator_dict={}    
    indicator_list=[]
    indicator_tmp_dict={}
    if 'indicators' in incident_summary[0].keys():
        for indic in incident_summary[0]['indicators']:
            if 'created' in indic.keys():
                indicator_tmp_dict['created'] = indic['created']   
            if 'modified' in indic.keys():
                indicator_tmp_dict['modified'] = indic['modified']  
            if 'source' in indic.keys():
                indicator_tmp_dict['source'] = indic['source'].replace('(cisco-jefflen)','')    
            if 'producer' in indic.keys():
                indicator_tmp_dict['producer'] = indic['producer'].replace('(cisco-jefflen)','')                   
            indicator_tmp_dict["description"]=indic["description"]
            indicator_tmp_dict["id"]=indic["id"]
            indicator_tmp_dict["schema_version"]=indic["schema_version"]
            indicator_tmp_dict["tlp"]=indic["tlp"]
            indicator_tmp_dict["title"]=indic["title"]
            indicator_tmp_dict["type"]=indic["indicator"]
            indicator_tmp_dict["timestamp"] =indic["timestamp"] 
            indicator_tmp_dict["modified"]=indic["modified"]
            indicator_tmp_dict["valid_time"]=indic["valid_time"]
            indicator_list.append(indicator_tmp_dict)  
    indicator_dict['context']={}
    indicator_dict['context']['indicators']=indicator_list
    return(indicator_dict)
    
def create_bundle(incident_json,sightings,relationships,source):
    bundle_json = {}
    bundle_json["source"] = source   
    print('   - Adding Incident payload to Bundle')
    incidents = []
    incidents.append(json.loads(incident_json))
    bundle_json["incidents"] = incidents
    print('   - Adding Sighting payload to Bundle')
    bundle_json["sightings"] = sightings
    print('   - Adding relationship payload ( Sighting to Incident )  to bundle')
    bundle_json["relationships"] = relationships
    print()       
    print('-Bundle JSON Paylod :')
    print(yellow(json.dumps(bundle_json,sort_keys=True,indent=4, separators=(',', ': ')),bold=True))
    return json.dumps(bundle_json)
    
def create_incident(host_for_token,access_token,bundle):
    '''
        create the new incident 
    '''
    print()
    print(yellow("  - Let's connect to XDR API to create the Incident into XDR",bold=True))
    print()
    #url = f"{host}/iroh/private-intel/bundle/import?external-key-prefixes=sxo" 
    url = f"{host_for_token}/iroh/private-intel/bundle/import?external-key-prefixes=sxo"
    print('url : ',url)
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    response = requests.post(url, data=bundle,headers=headers)
    print()  
    print(response.status_code)
    print(response.json())    
    if response.status_code==401:
        access_token=get_ctr_token(host_for_token)
        headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}        
        response = requests.post(url, data=bundle,headers=headers)           
    if response.status_code==200:
        print(green(response.status_code,bold=True))
        print()         
        print(green("Ok Done Incident created",bold=True))         
        print()    
        #print(response.json())    
        print(cyan(json.dumps(response.json(),sort_keys=True,indent=4, separators=(',', ': ')),bold=True))
        print() 
    return 1
    
def create_new_indicator(host,access_token,the_new_indicator):
    '''
        create the new indicator
    '''
    print()
    print(yellow("  - Let's connect to XDR API to create a new Indicator into XDR",bold=True))
    print()
    #url = f"{host}/iroh/private-intel/bundle/import?external-key-prefixes=sxo" 
    url = f"{host}/ctia/indicator"
    print('url : ',url)
    headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}
    print()
    print(" new indicator is :",the_new_indicator)
    print()
    response = requests.post(url, data=the_new_indicator,headers=headers)
    print()  
    print(response.status_code)
    #print(cyan(response.json(),bold=True))    
    if response.status_code==401:
        access_token=get_ctr_token(host_for_token)
        headers = {'Authorization':'Bearer {}'.format(access_token), 'Content-Type':'application/json', 'Accept':'application/json'}        
        response = requests.post(url, data=the_new_indicator,headers=headers)           
    if response.status_code==200 or response.status_code==201:
        print(green(response.status_code,bold=True))
        print()         
        print(green("Ok Done Indicator created",bold=True))         
        print()    
        #print(response.json())    
        print(cyan(json.dumps(response.json(),sort_keys=True,indent=4, separators=(',', ': ')),bold=True))
        new_indicator_id=response.json()['id']
        print() 
    return (new_indicator_id)
    
def get_incident_indicators():
    global indicator_map
    indicator_list=[]
    for item0 in incident_summary[0]['context']['indicators']: 
        #print("Indicator :",yellow(item0["title"] ,bold=True))
        #print(green(item0,bold=True))
        indicator_map[item0["id"]]={"old_id":item0["id"]}
        indicator_list.append(item0)       
    return(indicator_list)
    
if __name__ == "__main__":
    print(yellow("- Step 0 read XDR Tenant details and credentials",bold=True))
    if method=="config.txt":
        with open('config.txt','r') as file:
            text_content=file.read()
        ctr_client_id,ctr_client_password,host,SecureX_Webhook_url,DESTINATION_ROOM_ID,BOT_ACCESS_TOKEN,host_for_token = parse_config(text_content)
    print()
    #print('ctr_client_id :',ctr_client_id)
    #print('ctr_client_password :',ctr_client_password)
    #print('host : ',host )
    #print('SecureX_Webhook_url :',SecureX_Webhook_url)
    #print('BOT_ACCESS_TOKEN : ',BOT_ACCESS_TOKEN)
    #print('DESTINATION_ROOM_ID : ',DESTINATION_ROOM_ID)
    #print('host_for_token : ',host_for_token)
    print(yellow("Step 2 check if current CTR access token valid",bold=True))
    access_token=check_ctr_token(host,host_for_token,ctr_client_id,ctr_client_password)
    #print('access_token :',cyan(access_token,bold=True))
    if access_token==0:
        print(red("Error . Can't get CTR Token",bold=True))
        sys.exit()
    else:
        print(green("Ok Token = Success",bold=True))
    print()
    print(yellow("- Step 0 read incident summary json file",bold=True))
    incident_summary=read_incident_summary()
    print()
    print(yellow("- Step 1 get Incident Indicators and create them into the new tenant ",bold=True))
    print()
    indicator_list=get_incident_indicators()    
    for indicator in indicator_list:
        new_indicator_dict={}
        #the_source=indicator["source"]
        the_source=SOURCE_FOR_EVERYTHING
        print("===========================")
        print(cyan(indicator,bold=True))        
        new_indicator_dict={
    "created": indicator["created"],
    "description": indicator["description"],
    "modified": dateTime.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "producer": indicator["producer"],
    "schema_version": indicator["schema_version"],
    "source": the_source,
    "timestamp": indicator["timestamp"],
    "title": indicator["title"],
    "tlp": indicator["tlp"],
    "type": "indicator",
    "valid_time": {
        "end_time": indicator["valid_time"]["end_time"],
        "start_time": indicator["valid_time"]["start_time"]
    }
}   
        if "external_ids" in indicator.keys():
            new_indicator_dict["external_ids"]=indicator["external_ids"]     
        print()
        print(yellow(new_indicator_dict,bold=True))
        print()
        #new_indicator_json=json
        Indicator_json=json.dumps(new_indicator_dict)
        new_indicator_id=create_new_indicator(host,access_token,Indicator_json)
        indicator_map[indicator["id"]]['new_id']=new_indicator_id
        new_indicator_dict.clear()
        print()
        print('----------------')
    print('Indicator old to new map :\n',indicator_map)
    print()
    print(yellow("- Step 2 create Incident JSON payload",bold=True))
    incident_json,incident_xid=create_incident_json()
    print()
    print(yellow("- Step 3 create Incident Sightings JSON payload",bold=True))
    sightings = []
    relationships = []
    indicators=[]
    for this_sighting in incident_summary[0]['context']['sightings']: 
        print(green(this_sighting,bold=True))  
        # Add here the piece of code that select or not the current sighting  YES_SELECT_THIS_SIGHTING=0  = we don t select the Sighting
        YES_SELECT_THIS_SIGHTING=1 # let s select every sightings
        if YES_SELECT_THIS_SIGHTING:
            sighting_xid = create_sighting_xid("Sighting created for asset enrichment test")
            sighting_transient_id="transient:"+sighting_xid
            print("  - This Sighting_transient_id : ",cyan(sighting_transient_id,bold=True))
            print("  - Create This Sighting json payload : ",cyan(sighting_transient_id,bold=True))
            sighting=create_sighting_json(sighting_xid,this_sighting)
            sightings.append(json.loads(sighting)) # adding this sighting to sighting list
            print('   -- ok done')
            #a=input('STOP')
            print(yellow("- Step 2b Create Relationship payload for sighting to Incident memberships. Sighting is member-of Incident",bold=True))
            relationship_xid=generate_relationship_xid(sighting_transient_id,incident_xid)
            relationship=create_relationship_object(sighting_transient_id,incident_xid,relationship_xid,"member-of")    
            relationships.append(json.loads(relationship)) # adding this relationship to  relationship list
            
            print(yellow("- Step 2c Create Relationship payload for sighting to Indicator relationship",bold=True))
            if 'relationships' in incident_summary[0]['context'].keys():
                for rel in incident_summary[0]['context']['relationships']:
                    if rel['relationship_type']=='sighting-of' and rel['source_ref']==this_sighting['id']:
                        print('-------------')
                        print('this_sighting id : \n',this_sighting['id'])
                        print('source_ref : \n',rel['source_ref'])
                        print()
                        print('relationship :\n',cyan(rel,bold=True))
                        the_new_indicator_id=indicator_map[rel['target_ref']]['new_id']
                        print()
                        print('new indicator id :\n',cyan(the_new_indicator_id,bold=True))                    
                        relationship_xid=generate_relationship_xid(the_new_indicator_id,incident_xid)
                        relationship=create_relationship_object(sighting_transient_id,the_new_indicator_id,relationship_xid,"sighting-of")    
                        relationships.append(json.loads(relationship)) # adding this relationship to  relationship list                           
    print()
    print("Sightings JSON : \n",yellow(sightings,bold=True))
    for item in sightings:
        print('----------------------')
        print(green(item))
    print()
    a=input('SIGHTINGS JSON = DONE -> type enter to CONTINUE ')
    for item in relationships:
        print('----------------------')
        print(green(item))
    print()
    a=input('RELATIONSHIPS JSON = DONE -> type enter to  CONTINUE ')
    print()
    source_for_bundle=SOURCE_FOR_EVERYTHING
    print()
    print(yellow("- Step 4 create Bundle JSON payload => Put everything together",bold=True))
    bundle=create_bundle(incident_json,sightings,relationships,source_for_bundle)
    print()
    print(yellow("  - Ok Bundle JSON payload is ready",bold=True))
    print()
    print(yellow(" OKAY Ready to create the Incident In destination XDR tenant",bold=True))
    print()
    print(yellow("Step 5 Let's go !",bold=True))
    print()
    print('BUNDLE TO BE SENT Is bellow ')
    print(cyan(bundle,bold=True))
    a=input(' CONTINUE and create this incident into the destination XDR Tenant')
    create_incident(host_for_token,access_token,bundle)                                                                             