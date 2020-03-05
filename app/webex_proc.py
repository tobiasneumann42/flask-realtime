##!/usr/bin/python3

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
import asyncio
import base64
from typing import Callable, Tuple
from datetime import timedelta
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
				auth=HTTPBasicAuth('elastic', 'C1sco12345'),
				headers={'Content-type': 'application/json', 'Accept': 'text/plain'},
				verify="/home/flaskdemo/app/ad1_ca.cer")
	log.debug(f' get_KMS_requests response {response}')
	jResp = json.loads(response.content.decode('utf-8'))
	return jResp 

def get_user_info_elastic(useruuid):
	url = 'https://elk.dcloud.cisco.com:9200/_search'
	response = requests.post( url,
				auth=HTTPBasicAuth('elastic', 'C1sco12345'),
				verify="/home/flaskdemo/app/ad1_ca.cer",
				headers={ 'Content-Type': 'application/json' },
				data=json.dumps({
    					'_source': ['userinfo'],
						'from' : 0, 'size' : 1,
						'query': {
				   			'bool': {
				      				'must': [
										{
											'match': {
												'userId': {	'query': useruuid }
											}
										},
										{
											'exists': { 'field': 'userinfo' }
										}
				      				]
				    		}
						}
				}) )
	jResp = json.loads(response.content.decode('utf-8'))
	resp = {}
	# check if uuid already in elastic - number of hits returnes > 0
	if jResp['hits']['total']['value'] > 0:
		# get userinfo 
		if 'userinfo' in jResp['hits']['hits'][0]['_source']:
			resp['userinfo'] = jResp['hits']['hits'][0]['_source']['userinfo']
			print("Returned userinfo object get_user_elastic: ", resp)
			return resp
	else:
		return False

def get_user_info_webex(useruuid, authtoken):
	url = 'https://api.ciscospark.com/v1/people/'+useruuid
	auth = 'Bearer ' + authtoken
	logging.debug('Webex API lookup URL & access token: %s %s ', url, auth )
	response = requests.get ( url, headers={
					'Content-Type': 'application/json',
					'Authorization': auth
				})
	if response.status_code == 200: 
		jResp = json.loads(response.content.decode('utf-8'))
		resp = {}
		resp['userinfo'] = jResp
		logging.debug('Result 200 OK REST get_user_info_webex : %s ', resp['userinfo'] )
	else:
		print( "DEBUG: Result REST get_user_info_webex (raw) something went wrong: ", response )
		input("Press Enter to Continue...")
	return resp

def update_userinfo(userinfo, new_uinfo):
	url = 'https://elk.dcloud.cisco.com:9200/' + userinfo['_index'] + '/_doc/' + userinfo['_id']+ '/_update'
	log.info(f"updare_userinfo new user information: {new_uinfo['userinfo']['email']}")
	reponse = requests.post( url,
							 auth=HTTPBasicAuth('elastic', 'C1sco12345'),
							 verify="/home/flaskdemo/app/ad1_ca.cer",
							 headers={ 'Content-Type': 'application/json' },
                            data=json.dumps( {
				  	"doc": { "userinfo": new_uinfo['userinfo'] }
				} ) )
	jResp = json.loads(reponse.content.decode('utf-8'))
	resp = {}
	log.info(f'update_userinfo URL REST response: %s ', jResp )
	return

async def as_webex_proc(access_token: str, running: Callable[[], bool]):
    # run main task
    while  True:
        # run this every 10 sec
        time.sleep(10)
        jResponse = get_KMS_requests()

        log.info(f'Total number of records in search: {jResponse['hits']['total']}')

        records_updated = 0
        count = 0
        for userid in jResponse["hits"]["hits"]:
            # check for broken records with no userID field
            if 'userId' in userid["_source"]:
              # more housekeeping for empty records
              if userid["_source"]["userId"]:
                log.info(f'Checking userinfo already in elastic: {userid["_source"]["userId"]}' )
                uinfo = get_user_info_elastic( userid["_source"]["userId"] )
                if not uinfo:
                  log.info(f'No entry in elastic: {userid["_source"]["userId"]}' )
                  uinfo = get_user_info_webex( userid["_source"]["userId"], access_token )
                  log.info(f'Fetched entry from webex cloud: %s ', uinfo )
                # execute update
                if uinfo:
                  log.info(f'execute update: {userid["_index"]} - {userid["_id"]}')
                  update_userinfo( userid, uinfo )
                  records_updated  += 1
                  count += 1
        
        # print( "DEBUG: records updated: ", records_updated )
        log.info(f'records updated: {records_updated}')
        log.info(f'count: {count}')
    
    return


def webex_proc(sid: str, running: Callable[[], bool], user_id: str):
    # add a logging handler to stdout; logging output will be sent to the client via websocket
    format = logging.Formatter(fmt='{levelname:8s} webex_proc: {message}', style='{')
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(format)
    log.addHandler(handler)

    print("Webex_proc")
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

        # run asynchronous task
        asyncio.run(as_webex_proc(access_token.access_token, running))
        return

    except MyException:
        pass
    finally:
        # cleanup
        log.debug('cleaning up...')
        log.removeHandler(handler)
        print('-------------- Done ----------')


