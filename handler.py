import boto3
from botocore.exceptions import ClientError
import json
import logging
import os
import requests
from datetime import datetime
from collections import OrderedDict

logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

access_token = ""
refresh_token = ""


def apigee(event, context):
    ''' Entry Point '''
    logger.info('## ENVIRONMENT VARIABLES')
    logger.info(os.environ)
    logger.info('## EVENT')
    logger.info(event)

    ssm = boto3.client('ssm')

    def initialize_token(token_name, paramValue='placeholder', paramType='String'):
        if paramType == "SecureString":
            decryption = True
        else:
            decryption = False
        try:
            token = ssm.get_parameter(
                Name=token_name, WithDecryption=decryption)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ParameterNotFound':
                logger.warning(
                    'Parameter {0} not found, creating.'.format(token_name))
                ssm.put_parameter(
                    Name=token_name, Value=paramValue, Type=paramType)
                token = ssm.get_parameter(
                    Name=token_name, WithDecryption=decryption)
            else:
                logger.error("Unexpected error: {0}".format(e))
                raise Exception()
        return token['Parameter']['Value']

    def set_token(token_name, paramValue, paramType='String'):
        try:
            ssm.put_parameter(Name=token_name, Value=paramValue,
                              Type=paramType, Overwrite=True)
            logger.info("updated parameter: {0}".format(token_name))
        except ClientError as e:
            logger.error("Unexpected error: {0}".format(e))
            raise Exception()
        return True

    def renewRefreshToken(res, *args, **kwargs):
        if res.status_code == requests.codes['unauthorized']:
            logger.info('Refreshtoken expired, refreshing')

            apigee_user = initialize_token(
                '/lambda/apigee/api/apigee_user')
            apigee_passwd = initialize_token(
                '/lambda/apigee/api/apigee_passwd', paramType='SecureString')

            payload = {'username': apigee_user,
                       'password': apigee_passwd,
                       'grant_type': 'password'}
            headers = {'Authorization': 'Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0',
                       'Accept': 'application/json;charset=utf-8', 'Content-Type':	'application/x-www-form-urlencoded'}

            try:
                r = requests.post(tokenURL, data=payload, headers=headers)
                r.raise_for_status()
            except requests.exceptions.HTTPError as err:
                logger.critical(err)
                raise Exception(err)

            request = json.loads(r.text)

            global refresh_token
            refresh_token = request['refresh_token']
            logger.info('Saving new refresh token to aws.')
            set_token('/lambda/apigee/api/refresh_token',
                      paramValue=refresh_token, paramType='SecureString')

            req = res.request
            logger.info('Resending request {0} {1}'.format(
                req.method, req.url))
            req.body = {'refresh_token': refresh_token,
                        'grant_type': 'refresh_token'}

            return requests.post(req.url, data=req.body, headers=req.headers)

    def renewAccessToken(res, *args, **kwargs):
        if res.status_code == requests.codes['unauthorized']:
            logger.info('Accesstoken expired, refreshing')

            payload = {'refresh_token': refresh_token,
                       'grant_type': 'refresh_token'}
            headers = {'Authorization': 'Basic ZWRnZWNsaTplZGdlY2xpc2VjcmV0',
                       'Accept': 'application/json;charset=utf-8', 'Content-Type':	'application/x-www-form-urlencoded'}

            try:
                r = requests.post(tokenURL, data=payload, headers=headers, hooks={
                    'response': renewRefreshToken})
                r.raise_for_status()
            except requests.exceptions.HTTPError as err:
                logger.critical(err)
                raise Exception(err)

            request = json.loads(r.text)

            global access_token
            access_token = request['access_token']
            logger.info('Saving new access token to aws.')
            set_token('/lambda/apigee/api/access_token',
                      paramValue="Bearer " + access_token, paramType='SecureString')

            req = res.request
            logger.info('Resending request {0} {1}'.format(
                req.method, req.url))
            req.headers['Authorization'] = "Bearer " + access_token

            return requests.get(req.url, headers=req.headers)

    def getContent(var_id, var_info):
        payload = var_info
        headers = {'Authorization': access_token,
                   'Accept': 'application/json;charset=utf-8', 'Content-Type':	'application/x-www-form-urlencoded'}
        try:
            r = requests.get(apiURL+var_id, params=payload,
                             headers=headers, hooks={'response': renewAccessToken})
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.critical(err)
            raise Exception(err)

        request = json.loads(r.text)
        return request

    logger.info("initializing SSM Parameters")
    api_settings = initialize_token('/lambda/apigee/api/metrics/settings')
    tokenURL = initialize_token(
        '/lambda/apigee/api/tokenURL', paramValue='https://login.apigee.com/oauth/token')
    apiURL = initialize_token('/lambda/apigee/api/apiURL',
                              paramValue='https://apimonitoring.enterprise.apigee.com')
    access_token = initialize_token(
        '/lambda/apigee/api/access_token', paramType='SecureString')
    refresh_token = initialize_token(
        '/lambda/apigee/api/refresh_token', paramType='SecureString')

    splunkUrl = initialize_token('/lambda/apigee/splunk/splunkURL',
                                 paramValue='https://XXXsplunk_urlXXX/services/collector/raw')
    splunkAuthToken = initialize_token(
        '/lambda/apigee/splunk/splunkToken', paramType='SecureString')

    try:
        apiVariables = json.loads(api_settings)
    except ClientError as e:
        logger.error(
            "Error converting apiVariables to Json. Possibly not json. Error: {0}".format(e))
        raise Exception()

    for var_id, var_info in apiVariables.items():
        results = getContent(var_id, var_info)
        if len(results) > 0:
            resultArray = []

            for result in results['results'][0]['series']:

                for value in result['values']:

                    valueDict = OrderedDict()

                    if 'time' in result['columns']:
                        valueDict['time'] = ''

                    for tag in result['tags']:
                        valueDict[tag] = result['tags'][tag]

                    for i in range(len(value)):
                        valueDict[result['columns'][i]] = value[i]

                    resultArray.append(valueDict)

                    # Send data to Splunk
                    headers = {'Authorization': 'Splunk ' + splunkAuthToken}
                    print(valueDict)
                    try:
                        r = requests.post(
                            splunkUrl, json=valueDict, headers=headers)
                        r.raise_for_status()
                    except requests.exceptions.HTTPError as err:
                        logger.critical(err)
                        raise Exception(err)
            logger.info(
                '{0} records written to Splunk'.format(len(resultArray)))
        else:
            logger.warning("No Results found.")
