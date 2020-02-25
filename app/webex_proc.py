#!/usr/bin/python3

# Sample script to update Cisco KMS syslog records in elastic and add human readable
# user information. 
#
# Syslog messages received from Cisco Hybrid Data Security (HDS) contain only user
# representations based on UUIDs. To provide more detailed human readable information
# that can be used in ELK dashboards the scripts queries syslog records in ELK that 
# are missing user information and extracts the UUIDs.
# The sciprt will next check if a given UUID is already present in ELK from earlier 
# run. In this case the existing UUID-> user information is applied to the syslog record.
# In case the user information is not available in ELK the Cisco Webex API is authomatically
# quried to retrieve the required information from the cloud.
#
# Script requires a client_id, client_secret, refresh_token which can be optained from 
# developer.webex.com
#
# This sample script is provided as is. Cisco Systems does not provide any warranty or
# support. It is not intended for production deployment. Use at your own risk.


import sys
import os
import operator
import requests
import json
import codecs
import time
import logging
from collections import OrderedDict
from operator import itemgetter
from requests.auth import HTTPBasicAuth

import webexteamssdk

from .webexteamsasyncapi import WebexTeamsAsyncAPI
from .interactive import Token

log = logging.getLogger(__name__)

class MyException(Exception):
    pass

def get_KMS_requests():
	url = 'https://elk.dcloud.cisco.com:9200/_search?pretty=true'
	data =  '''{
            "_source": [
                "userId"
            ],
            "size": 10000,
            "query": {
                "constant_score": {
                    "filter": {
                        "bool": {
                            "must": {
                                "match": {
                                    "hdsaction": {
                                        "query": "KMS:REQUEST"
                                    }
                                }
                            },
                            "must_not": [
                                {"exists": {"field": "userinfo.created"}},
                                {"match":{"hdsuserID":"null"}}
                                ]
                            }
                        }
                    }
                }
            }'''
	response = requests.get(url,
				data = data,
				auth=HTTPBasicAuth('elastic', 'Cisco,123'),
				headers={'Content-type': 'application/json', 'Accept': 'text/plain'},
				verify="ad1_ca.cer")
	jResp = json.loads(response.content.decode('utf-8'))
	return jResp 

def get_user_info_elastic(useruuid):
	url = 'https://elk.dcloud.cisco.com:9200/_search'
	response = requests.post( url,
				auth=HTTPBasicAuth('elastic', 'Cisco,123'),
				verify="ad1_ca.cer",
				headers={ 'Content-Type': 'application/json' },
				data=json.dumps({
    					'_source': ['userinfo'],
					'from' : 0, 'size' : 1,
					'query': {
				   		'bool': {
				      			'must': [
					 			{ 'match': { 'userId': {
										'query': useruuid
							    			}
									}
								},
								{ 'exists': { 'field': 'userinfo' }
								}
				      			]
				    		}
					}
				}) )
	jResp = json.loads(response.content.decode('utf-8'))
	resp = {}
	# print( "Result REST get_user_elastic: ", jResp )
        # check if uuid already in elastic - number of hits returnes > 0
	if jResp['hits']['total']['value'] > 0:
		# get userinfo 
		if 'userinfo' in jResp['hits']['hits'][0]['_source']:
			resp['userinfo'] = jResp['hits']['hits'][0]['_source']['userinfo']
			# print("Returned userinfo object get_user_elastic: ", resp)
			return resp
	else:
		return False

def get_user_info_webex(useruuid, access_token):
        api = WebexTeamsAsyncAPI(access_token)

        people = api.list_people(p_id=useruuid)        
	log.debug(f' webex people api return {people}')
        return people

def update_userinfo(userinfo, new_uinfo):
	url = 'https://elk.dcloud.cisco.com:9200/' + userinfo['_index'] + '/_doc/' + userinfo['_id']+ '/_update'
	# print( "DEBUG: update_userinfo URL: ", url )
	# print( "DEBUG: update_userinfo new user information: ", new_uinfo['userinfo'] )
	log.debug('updare_userinfo new user information: %s ', new_uinfo['userinfo'] )
	reponse = requests.post( url,
							 auth=HTTPBasicAuth('elastic', 'Cisco,123'),
							 verify="ad1_ca.cer",
							 headers={ 'Content-Type': 'application/json' },
                            data=json.dumps( {
				  	"doc": { "userinfo": new_uinfo['userinfo'] }
				} ) )
	jResp = json.loads(reponse.content.decode('utf-8'))
	resp = {}
	# print( "update_userinfo URL REST reponse: ", jResp )
	log.debug('update_userinfo URL REST response: %s ', jResp )
	return

def webex_proc(sid: str, running: Callable[[], bool], user_id: str):
    # add a logging handler to stdout; logging output will be sent to the client via websocket
    format = logging.Formatter(fmt='{levelname:8s} get_uuids: {message}', style='{')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(format)
    log.addHandler(handler)

    try:
        log.debug(f'user_id={user_id}, sid={sid}')

        # First get an access token
        log.debug(f'trying to get access token')
        access_token = Token.get_token(user_id=user_id)
        if access_token is None:
            log.error(f'Failed to get access token for {user_id}')
            raise MyException

        lifetime_remaining = timedelta(seconds=access_token.lifetime_remaining_seconds)
        log.debug(f'access token still valid for {lifetime_remaining}')

        # need to make sure that the access token is good for another 10 minutes
        if lifetime_remaining.total_seconds() < 600:
            access_token.refresh()
            log.debug(
                f'had to refresh access token. New lifetime: '
                f'{timedelta(seconds=access_token.lifetime_remaining_seconds)}')

        # run main task
        while  True:
          # run this every 10 sec
          time.sleep(10)	
          jResponse = get_KMS_requests()

          log.debug('Total number of hits in search: %s ',  jResponse['hits']['total'])

          records_updated = 0
          count = 0
          for userid in jResponse["hits"]["hits"]:
            # log.debug('search result: %s ', userid)
            # check for broken records with no userID field
            if 'userId' in userid["_source"]:
              # more housekeeping for empty records
              if userid["_source"]["userId"] == 'null': continue
              if userid["_source"]["userId"]:
                log.debug('checking userinfo already in elastic: %s ', userid["_source"]["userId"] )
                uinfo = get_user_info_elastic( userid["_source"]["userId"] )
                if not uinfo:
                  # print( "DEBUG: No entry in elastic: ", userid["_source"]["userId"] )
                  log.debug('No entry in elastic: %s ', userid["_source"]["userId"] )
                  uinfo = get_user_info_webex( userid["_source"]["userId"], access_token )
                  # print( "DEBUG: Fetched entry from webex cloud: ", uinfo )
                  log.debug('Fetched entry from webex cloud: %s ', uinfo )
                  # print( "DEBUG: execute main loop update: ", userid["_index"], userid["_id"])
                  log.debug('execute main loop update: %s - %s', userid["_index"], userid["_id"])
                  update_userinfo( userid, uinfo )
                  records_updated  += 1
                  count += 1
          # print( "DEBUG: records updated: ", records_updated )
          log.debug('records updated: %s ', records_updated )
          log.debug('count: %s ', count)
        return

    except MyException:
        pass
    finally:
        # cleanup
        log.debug('cleaning up...')
        log.removeHandler(handler)
        print('-------------- Done ----------')


