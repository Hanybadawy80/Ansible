""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import argparse, json, logging, requests, socket, sys, time, xmltodict, urllib3, os
import requests_oauthlib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from os import path
from threading import Thread
from exchangelib.protocol import close_connections
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from requests_ntlm import HttpNtlmAuth

sys.path.append(path.abspath('/opt/cyops-integrations/integrations'))
from integrations.crudhub import make_request


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from configuration import ExchangeConfiguration
from exchange_const import OAUTH_PERMISSION_MAP, ACCESS_TYPE_MAP, OAUTH_AUTHENTICATION_MAP

LOG_DIR_PATH = '/var/log/cyops/cyops-integrations/exchange/'
LOG_FILE_PATH = path.join(LOG_DIR_PATH, 'exchange_listener.log')
os.makedirs(LOG_DIR_PATH, exist_ok=True)
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(message)s')
handler = logging.FileHandler(LOG_FILE_PATH)
handler.setFormatter(formatter)
logger.addHandler(handler)

threads = {}
client_count = 0
MAX_LENGTH = 4096
SSL_VERIFY = False
cs_host = 'localhost'
num_of_seconds_to_wait = 30
seconds_to_wait = 60
max_retry = 20
MAX_RETRY = 5
DELAY_TIME = 15
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
AUTH_TYPE_MAP = {
    "NTLM": HttpNtlmAuth,
    "BASIC": HTTPBasicAuth,
    "DIGEST": HTTPDigestAuth,
    "OAUTH 2.0": requests_oauthlib.OAuth2
}

RESP_ERROR_MSG = {
    400: 'Bad/Invalid Request',
    401: 'Unauthorized: Provided credentials is Invalid',
    403: 'Access Denied',
    404: 'Not Found',
    500: 'Internal Server Error',
    503: 'Service Unavailable'
}

INBOX_ID = '<t:DistinguishedFolderId Id="inbox" />'
MAILBOX_ID = """<t:FolderId Id="{}" ChangeKey="{}" />"""

cloud_subscribe_to_stream_notification = """<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                       xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
                       xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
                       xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Header><RequestServerVersion Version="Exchange2013" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" soap:mustUnderstand="0"/></soap:Header>
          <soap:Body>
            <m:Subscribe>
              <m:StreamingSubscriptionRequest>
                <t:FolderIds>
                  {mailbox}
                </t:FolderIds>
                <t:EventTypes>
                    <t:EventType>NewMailEvent</t:EventType>
                    <t:EventType>ModifiedEvent</t:EventType>
                    <t:EventType>MovedEvent</t:EventType>
                </t:EventTypes>
              </m:StreamingSubscriptionRequest>
            </m:Subscribe>
          </soap:Body>
        </soap:Envelope>"""

on_prem_subscribe_to_stream_notification_xml = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" soap:mustUnderstand="0" />
  </soap:Header>
  <soap:Body>
    <m:Subscribe>
      <m:StreamingSubscriptionRequest>
        <t:FolderIds>
          {mailbox}
        </t:FolderIds>
        <t:EventTypes>
          <t:EventType>NewMailEvent</t:EventType>
          <t:EventType>ModifiedEvent</t:EventType>
          <t:EventType>MovedEvent</t:EventType>
        </t:EventTypes>
      </m:StreamingSubscriptionRequest>
    </m:Subscribe>
  </soap:Body>
</soap:Envelope>
"""

subscribe_for_impersonation_xml = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" soap:mustUnderstand="0" />
    <t:ExchangeImpersonation>
      <t:ConnectingSID>
        <t:SmtpAddress>{email}</t:SmtpAddress>
      </t:ConnectingSID>
    </t:ExchangeImpersonation>
  </soap:Header>
  <soap:Body>
    <m:Subscribe>
      <m:StreamingSubscriptionRequest>
        <t:FolderIds>
          {mailbox}
        </t:FolderIds>
        <t:EventTypes>
          <t:EventType>NewMailEvent</t:EventType>
          <t:EventType>ModifiedEvent</t:EventType>
          <t:EventType>MovedEvent</t:EventType>
        </t:EventTypes>
      </m:StreamingSubscriptionRequest>
    </m:Subscribe>
  </soap:Body>
</soap:Envelope>"""

get_stream_events_xml = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" soap:mustUnderstand="0" />
  </soap:Header>
  <soap:Body>
    <m:GetStreamingEvents>
      <m:SubscriptionIds>
        <t:SubscriptionId>{id}</t:SubscriptionId>
      </m:SubscriptionIds>
      <m:ConnectionTimeout>1</m:ConnectionTimeout>
    </m:GetStreamingEvents>
  </soap:Body>
</soap:Envelope>"""

convert_folder_id_xml = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="https://schemas.microsoft.com/exchange/services/2006/types">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" soap:mustUnderstand="0"/>
  </soap:Header>
  <soap:Body>
    <ConvertId xmlns="https://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="https://schemas.microsoft.com/exchange/services/2006/types"
               DestinationFormat="EwsId">
      <SourceIds>
        <t:AlternateId Format="EwsLegacyId" Id="{folder_id}"
                       Mailbox="{mailbox}}"/>
      </SourceIds>
    </ConvertId>
  </soap:Body>
</soap:Envelope>
"""

find_folder_xml = """<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013_SP1" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" soap:mustUnderstand="0" />
  </soap:Header>
  <soap:Body>
    <m:FindFolder Traversal="Deep">
      <m:FolderShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="folder:DisplayName" />
        </t:AdditionalProperties>
      </m:FolderShape>
      <m:IndexedPageFolderView MaxEntriesReturned="10" Offset="0" BasePoint="Beginning" />
      <m:Restriction>
        <t:IsEqualTo>
          <t:FieldURI FieldURI="folder:DisplayName" />
          <t:FieldURIOrConstant>
            <t:Constant Value="{folder_name}" />
          </t:FieldURIOrConstant>
        </t:IsEqualTo>
      </m:Restriction>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="msgfolderroot" />
      </m:ParentFolderIds>
    </m:FindFolder>
  </soap:Body>
</soap:Envelope>
"""

oauth_stream_events_xml = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2013" xmlns="http://schemas.microsoft.com/exchange/services/2006/types" soap:mustUnderstand="0" />
    <t:ExchangeImpersonation>
      <t:ConnectingSID>
        <t:SmtpAddress>{email}</t:SmtpAddress>
      </t:ConnectingSID>
    </t:ExchangeImpersonation>
  </soap:Header>
  <soap:Body>
    <m:GetStreamingEvents>
      <m:SubscriptionIds>
        <t:SubscriptionId>{id}</t:SubscriptionId>
      </m:SubscriptionIds>
      <m:ConnectionTimeout>1</m:ConnectionTimeout>
    </m:GetStreamingEvents>
  </soap:Body>
</soap:Envelope>"""

XML_HEADERS = """<Version ="Exchange2013">{event_response}</Version>"""

event_type = [':NewMailEvent', ':ModifiedEvent', ':MovedEvent']

NEW_MAIL_EVENT = ':NewMailEvent'
NEW_EVENT = 1
NO_NEW_EVENT = 2
UNABLE_RETRIEVE_EVENT = 'Unable to retrieve events for this subscription'
EVENT_RESPONSE = {1: 'New event occurred', 2: 'No new event occurred'}


class AuthTypeNotSupported(Exception):
    pass


def make_rest_call(endpoint, auth, payload, verify_ssl):
    headers = {'content-type': 'text/xml'}
    retry_count = 0
    while retry_count < MAX_RETRY:
        response = requests.post(endpoint, auth=auth, data=payload, headers=headers, verify=verify_ssl, timeout=90)
        if response.ok:
            return response.text
        elif response.status_code == 500:
            retry_count += 1
            if retry_count >= MAX_RETRY:
                logger.error("Retry limit reached to subscribe notification: {}".format(retry_count))
            else:
                logger.error("Retries attempted to subscribe notification: {}".format(retry_count))
                time.sleep(DELAY_TIME)
        else:
            break
    logger.error("failed to subscribe to notification, response status code: {}".format(response.status_code))
    error_msg = RESP_ERROR_MSG[response.status_code]
    error = error_msg if error_msg else response.text
    raise Exception(error)


def handle_response_error(resp):
    try:
        xml_data = XML_HEADERS.format(event_response=resp)
        soup = BeautifulSoup(xml_data, 'xml')
        if 'ResponseClass="Error"' in str(resp):
            error_msg = soup.find('MessageText')
            if error_msg:
                logger.error('{}'.format(error_msg.text))
            else:
                logger.debug('Notification Service response: {}'.format(resp))
        logger.debug("Waiting for {} seconds.".format(seconds_to_wait))
        time.sleep(seconds_to_wait)
    except Exception as e:
        logger.error(e)


def get_subscription_id(url, username, password, auth_type, verify_ssl, body, client_id, access_token):
    auth_method = AUTH_TYPE_MAP.get(auth_type.upper())
    if not auth_method:
        raise AuthTypeNotSupported("Auth type: {} does not supported".format(auth_type))
    auth = auth_method(client_id=client_id, token=access_token) if auth_type == 'OAUTH 2.0' else auth_method(username,
                                                                                                             password)
    resp = make_rest_call(url, auth=auth, payload=body, verify_ssl=verify_ssl)
    # logger.debug("API Response: {}".format(resp)) # if more details required uncomment this line
    if resp:
        try:
            json_response = xmltodict.parse(resp)
            id = json_response['s:Envelope']['s:Body']['m:SubscribeResponse']['m:ResponseMessages'][
                'm:SubscribeResponseMessage']['m:SubscriptionId']
            logger.debug("subscription id: {}".format(id))
            return id
        except Exception as e:
            logger.error('Not able to convert response from xml to json')
            logger.error('Unable to fetch subscription ID')
            handle_response_error(resp)
    return None


def subscribe_to_stream_notification(url, username, password, exchange, auth_type, verify_ssl, mailbox, client_id,
                                     access_token):
    if exchange == 'On-Premises':
        body = on_prem_subscribe_to_stream_notification_xml.format(mailbox=mailbox)
    else:
        body = cloud_subscribe_to_stream_notification.format(mailbox=mailbox)
    return get_subscription_id(url, username, password, auth_type, verify_ssl, body, client_id, access_token)


def subscribe_for_impersonation(url, username, password, email, auth_type, verify_ssl, mailbox, client_id,
                                access_token):
    body = subscribe_for_impersonation_xml.format(email=email, mailbox=mailbox)
    return get_subscription_id(url, username, password, auth_type, verify_ssl, body, client_id, access_token)


def get_stream_events(sub_id, url, username, password, email, auth_type, folder, verify_ssl, client_id, access_token):
    auth_method = AUTH_TYPE_MAP.get(auth_type.upper())
    if not auth_method:
        logger.error("Auth type is: {} not supported".format(auth_type))
        raise AuthTypeNotSupported("Auth type is: {} not supported".format(auth_type))
    if auth_type == 'OAUTH 2.0':
        body = oauth_stream_events_xml.format(email=email, id=sub_id)
        resp = make_rest_call(url, auth=auth_method(client_id=client_id, token=access_token), payload=body,
                              verify_ssl=verify_ssl)
    else:
        body = get_stream_events_xml.format(id=sub_id)
        resp = make_rest_call(url, auth=auth_method(username, password), payload=body, verify_ssl=verify_ssl)
    if resp:
        if 'ResponseClass="Error"' in str(resp):
            handle_response_error(resp)
            return str(resp)
        else:
            xml_data = XML_HEADERS.format(event_response=resp)
            soup = BeautifulSoup(xml_data, 'lxml')
            logger.debug("Monitoring folder is: {}".format(folder))
            unread_count = soup.find('UnreadCount') or soup.find('t:unreadcount')
            if unread_count:
                unread_count = int(unread_count.text)
            logger.debug("Unread Email count: {}".format(unread_count))
            event = [event for event in event_type if event in str(resp)]
            logger.debug("{} Event occurred.".format(event))

            if NEW_MAIL_EVENT in event or (event and unread_count):
                return NEW_EVENT
            else:
                logger.debug('No new event occurs on email: {}'.format(email))
                return NO_NEW_EVENT


def health_check(host, folder, auth_method, config_params):
    thread_key = get_key(host, folder, auth_method, config_params)
    email = config_params.get('email_address')
    if threads.get(thread_key, False):
        if threads[thread_key]['result']:
            if not threads[thread_key]['threadobj'].is_alive():
                message = 'Notification service terminated unexpectedly for email {0}'.format(email)
                logger.error(message)
                return -1, message
            else:
                message = 'Found running notification for %s email and %s folder' % (email, folder)
                logger.debug(message)
                return 0, message
        else:
            return -1, threads[thread_key]['message']
    else:
        message = 'Notification Service not running for server {0} user {1}. Deactivate and activate the connector to restart the listeners.'.format(
            host, config_params.get('username'))
        logger.error(message)
        return -1, message


def shutdown_server():
    logger.info('in shutdown server action')
    global threads, client_count
    client_count = len(threads)
    threads = {}
    timeout = time.time() + 40
    while time.time() < timeout:
        if client_count <= 0:
            break
    return 0, "No active notification listeners."


class NotifierThread(Thread):
    def __init__(self, sub_id, host, trigger, thread_key, access_type, exchange, auth_type, verify_ssl, mailbox, folder,
                 config_params):
        Thread.__init__(self)
        self.sub_id = sub_id
        self.host = host
        self.username = config_params.get('username')
        self.password = str(config_params.get('password'))
        self.email = config_params.get('email_address')
        self.accessType = access_type
        self.trigger = trigger
        self.thread_key = thread_key
        self.exchange = exchange
        self.verify_ssl = verify_ssl
        self.auth_type = auth_type.upper()
        self.mailbox = mailbox
        self.folder = folder
        self.client_id = config_params.get('client_id')
        self.client_secret = config_params.get('client_secret')
        self.tenant_id = config_params.get('tenant_id')
        self.access_token = None

    def get_subscription(self):
        if self.accessType == 'IMPERSONATION':
            self.sub_id = subscribe_for_impersonation(self.host, self.username, self.password,
                                                      self.email, self.auth_type, self.verify_ssl, self.mailbox,
                                                      self.client_id, self.access_token)
        else:
            self.sub_id = subscribe_to_stream_notification(self.host, self.username, self.password,
                                                           self.exchange, self.auth_type, self.verify_ssl, self.mailbox,
                                                           self.client_id, self.access_token)

    def forward_to_cyops(self, trigger):
        full_uri = '/api/triggers/1/' + trigger
        try:
            response = make_request(full_uri, 'POST', body={}, __async=True, verify=False)
            task_id = response.get('task_id')
            if task_id:
                logger.debug('playbook triggered successfully')
        except Exception as e:
            if 'Not Found' in str(e):
                logger.error('failed to trigger playbook, playbook may be deactivate state. activate playbook first')
            else:
                logger.exception('failed to triggered playbook: {}'.format(e))

    def validate_oauth_token(self, expires_in):
        try:
            ts_now = time.time()
            if expires_in and ts_now > int(float(expires_in)):
                refresh_token = threads.get(self.thread_key, {}).get('token_resp', {}).get('refresh_token')
                token_resp = ExchangeConfiguration.generate_token(self.client_id, self.client_secret, self.tenant_id,
                                                                  refresh_token, self.verify_ssl)
                expires_in = ts_now + token_resp['expires_in']
                threads.get(self.thread_key, {}).update({'token_resp': token_resp, 'expires_in': expires_in})
                return token_resp
            else:
                return threads.get(self.thread_key, {}).get('token_resp')
        except Exception as err:
            logger.error(err)
            raise Exception(err)

    def run(self, **kwargs):
        global client_count
        retries = 0
        while True:
            if threads.get(self.thread_key):
                expires_in = threads.get(self.thread_key, {}).get('expires_in')
                if self.auth_type == "OAUTH 2.0":
                    self.access_token = self.validate_oauth_token(expires_in)
                try:
                    if self.sub_id:
                        response = get_stream_events(self.sub_id, self.host, self.username, self.password,
                                                     self.email, self.auth_type, self.folder, self.verify_ssl,
                                                     self.client_id, self.access_token)
                        logger.debug('response of stream events: {}'.format(
                            EVENT_RESPONSE.get(response) if EVENT_RESPONSE.get(response) else response))
                        if response:
                            retries = 0
                            if response is NEW_EVENT:
                                logger.debug('New mail received on email: {}'.format(self.email))
                                logger.debug('triggering {} API trigger playbook'.format(self.trigger))
                                self.forward_to_cyops(self.trigger)
                            elif response is NO_NEW_EVENT:
                                continue
                            elif UNABLE_RETRIEVE_EVENT in str(response):
                                # when "Unable to retrieve events for this subscription" error occurred
                                self.get_subscription()
                            else:
                                # response fetch but error occurred in response.
                                self.get_subscription()
                        else:
                            time.sleep(num_of_seconds_to_wait)
                            # 401 or any other cases response got empty.
                            self.get_subscription()
                    else:
                        # subscription got empty or None.
                        self.get_subscription()
                except (urllib3.exceptions.ProtocolError, requests.exceptions.ProxyError,
                        requests.exceptions.ChunkedEncodingError):
                    self.forward_to_cyops(self.trigger)
                # Retry is not attempted when Auth Type is not supported.
                except AuthTypeNotSupported as e:
                    logger.error(e)
                    break
                except Exception as err:
                    logger.error(err)
                    retries += 1
                    if retries > max_retry:
                        logger.error("Max retries limit exceeded")
                        logger.error(
                            "Listener is in Stopped state. Returning. Deactivate and activate the connector to restart the listeners")
                        logger.error("Notification service is down on email: {}".format(self.email))
                        break
                    logger.warn("Retry attempts: {}".format(retries))
                    logger.warn("Trying to connect after {} seconds".format(seconds_to_wait))
                    time.sleep(seconds_to_wait)
            else:
                logger.error("Notification service stopped on email: {}".format(self.email))
                logger.debug("Thread Stopped Successfully {}".format(self.thread_key))
                break
        client_count -= 1
        threads.pop(self.thread_key, '')


def get_key(host, folder, auth_method, config_params):
    email = config_params.get('email_address')
    access_type = OAUTH_AUTHENTICATION_MAP.get(config_params.get('access_type'), '')
    if auth_method == 'OAUTH':
        client_id = config_params.get('client_id')
        tenant_id = config_params.get('tenant_id')
        return host.upper() + '-' + client_id + '-' + email + '-' + tenant_id + '-' + access_type + '-' + folder
    else:
        username = config_params.get('username')
        return host.upper() + '-' + username + '-' + email + '-' + folder


def get_mailbox(client, mailbox_path):
    try:
        mailbox_path = mailbox_path.replace('\\', '/')
        if mailbox_path[0] == "/":
            mailbox_path = mailbox_path[1:]
        mailbox_path = mailbox_path.split("/")

        if mailbox_path[0].lower() == 'inbox':
            folder = client.inbox
            mailbox_path.pop(0)
        else:
            folder = client.msg_folder_root
        for next_folder in mailbox_path:
            folder = folder / next_folder
        folder_id = folder.id
        change_key = folder.changekey
        mailbox_string = MAILBOX_ID.format(folder_id, change_key)
        return mailbox_string
    except Exception as e:
        logger.error('{}'.format(e))
        raise Exception('{}'.format(e))


def get_config_params(config):
    username = config.get('username')
    password = config.get('password')
    tenant_id = config.get('tenant_id')
    client_id = config.get('client_id')
    client_secret = config.get('client_secret')
    auth_type = config.get('auth_type', '')
    access_token = config.get('access_token')
    return username, password, client_id, client_secret, tenant_id, access_token, auth_type


def start_thread(host, trigger, access_type, exchange, verify_ssl, folder, auth_method, expires_in, config_params):
    email = config_params.get('email_address')
    thread_key = get_key(host, folder, auth_method, config_params)
    message = ''
    config_obj = ExchangeConfiguration(config_params, logger)
    credentials = config_obj.get_credentials()
    client = config_obj.get_exchange_client(email, credentials)
    logger.debug("exchange client is: {}".format(client))
    username, password, client_id, client_secret, tenant_id, access_token, auth_type = get_config_params(
        config_params)
    if client:
        auth_type = client.protocol.auth_type.upper()
        logger.debug("Auth type is: {}".format(auth_type))
        if auth_type == 'OAUTH 2.0':
            access_token = client.protocol.credentials.access_token
            if not expires_in:
                expires_in = access_token.get('expires_at')
        global threads
        if not threads.get(thread_key, False):
            threads[thread_key] = {"result": False, "message": "", "threadobj": {}, 'token_resp': access_token,
                                   'expires_in': expires_in}
        try:
            mailbox_string = get_mailbox(client, folder) if folder else INBOX_ID
            if not threads[thread_key]['result']:
                try:
                    access_type = ACCESS_TYPE_MAP.get(access_type) if auth_method == 'OAUTH' else access_type
                    if access_type == 'IMPERSONATION':
                        sub_id = subscribe_for_impersonation(host, username, password, email, auth_type, verify_ssl,
                                                             mailbox_string, client_id, access_token)
                    else:
                        sub_id = subscribe_to_stream_notification(host, username, password, exchange, auth_type,
                                                                  verify_ssl, mailbox_string, client_id, access_token)
                    thread_instance = NotifierThread(sub_id, host, trigger, thread_key, access_type, exchange,
                                                     auth_type, verify_ssl, mailbox_string, folder, config_params)
                    thread_instance.start()
                    threads[thread_key]['result'] = True
                    threads[thread_key]['threadobj'] = thread_instance
                    message = 'Notification service starting on email: {}'.format(email)
                    logger.debug(message)
                except Exception as e:
                    logger.exception("returning the exception %s" % e)
                    threads[thread_key]['message'] = str(e)
                    return -1, str(e)
            else:
                message = 'Notification Service already running for server {0} and email {1} '.format(host, email)
                return -1, message
        except Exception as e:
            logger.error(e)
            threads[thread_key]['message'] = str(e)
    else:
        message = 'Exchange client not created'
        return -1, message
    return 0, message


def stop_thread_and_process(host, folder, auth_method, config_params):
    message = ''
    email = config_params.get('email_address')
    thread_key = get_key(host, folder, auth_method, config_params)
    if threads.get(thread_key, False):
        threads.pop(thread_key, '')
        message = 'Notification Service stopped for email: %s' % email
    if threads == {}:
        logger.error('No active config, closing socket')
        serversocket.close()
        close_connections()
        sys.exit()
    return 0, message


def stop_thread(host, folder, auth_method, config_params):
    email = config_params.get('email_address')
    thread_key = get_key(host, folder, auth_method, config_params)
    if threads.get(thread_key, False):
        threads.pop(thread_key, '')
        message = 'Notification Service stopped for email: %s' % email
    else:
        message = 'Notification Service already stopped for server {0} and email{1}'.format(host, email)
        logger.exception(message)
    if threads == {}:
        logger.error('No active config, closing socket')
        serversocket.close()
        close_connections()
        logger.debug('server is stopped')
        sys.exit()
    return 0, message


def handle(clientsocket):
    payload_bytes = clientsocket.recv(MAX_LENGTH)
    if payload_bytes:
        payload = payload_bytes.decode('utf-8')
        parser = argparse.ArgumentParser(description='Exchange Mail Notification Actions')
        parser.add_argument('--start', help='Start Server', action='store_true', default=False, required=False)
        parser.add_argument('--stop', help='Stop Server', action='store_true', default=False, required=False)
        parser.add_argument('--delete', help='Stop Thread and Process', action='store_true', default=False,
                            required=False)
        parser.add_argument('--exit', help='Stop Server', action='store_true', default=False, required=False)
        parser.add_argument('--check', help='Check Health', action='store_true', default=False, required=False)
        parser.add_argument('--host', help='Configuration for mail notification', required=False)
        parser.add_argument('--ssl', help='SSL for server', required=False)
        parser.add_argument('--username', help='Mail username to forward data', required=False)
        parser.add_argument('--password', help='Mail password to forward data', required=False)
        parser.add_argument('--client_id', help='Client ID for OAuth2', required=False)
        parser.add_argument('--client_secret', help='Client secret for OAuth2', required=False)
        parser.add_argument('--tenant_id', help='Tenant ID for OAuth2', required=False)
        parser.add_argument('--trigger', help='Configuration for trigger playbook', required=False)
        parser.add_argument('--email', help='Email to access mailbox', required=False)
        parser.add_argument('--folder', help='Folder name of the mailbox to access', required=False, nargs='*')
        parser.add_argument('--accessType', help='Access type of user', required=False)
        parser.add_argument('--access_token', help='The access_token for the authorization', required=False)
        parser.add_argument('--expires_in', help='The token expiration time in epoch', required=False)
        parser.add_argument('--verify_ssl', help='Specifies SSL certificate for the Exchange Web Services',
                            required=False)
        parser.add_argument('--exchange', help='Specifies hosted or cloud exchange instance', required=False)
        parser.add_argument('--auth_method', help='Specifies Auth method', required=False)
        status = -1
        args_parsed = False
        message = ''
        args = ''
        try:
            # so that the main program does not exit if parsing fails
            payload = payload.replace('On-premises/Outlook Live', 'On-Premises')
            args = parser.parse_args(payload.split())
            args_parsed = True
        except SystemExit as se:
            message = se
            logger.exception(se)
        if args_parsed:
            try:
                if args.exit:
                    logger.debug('command to exit server')
                    status, message = shutdown_server()
                else:
                    if not args.host:
                        raise Exception('host is mandatory arguments')
                    if not args.username:
                        raise Exception('username is a mandatory argument')
                    if args.ssl:
                        ssl = args.ssl
                    else:
                        ssl = 'https'
                    host = args.host
                    auth_method = args.auth_method
                    access_type = OAUTH_PERMISSION_MAP.get(
                        args.accessType) if auth_method == 'OAUTH' else args.accessType
                    verify_ssl = args.verify_ssl
                    expires_in = args.expires_in
                    if expires_in:
                        expires_in = eval(expires_in)
                    if verify_ssl:
                        verify_ssl = eval(verify_ssl)
                    exchange = args.exchange
                    parse_object = urlparse(host)
                    if parse_object.scheme:
                        host = parse_object.netloc
                    service_endpoint = '{0}://{1}/EWS/Exchange.asmx'.format(ssl, host)
                    expires_in = float(expires_in) if expires_in else expires_in
                    config_params = {'username': args.username, 'password': args.password, 'client_id': args.client_id,
                                     'client_secret': args.client_secret, 'tenant_id': args.tenant_id,
                                     'access_type': access_type, 'auth_method': args.auth_method,
                                     'host': service_endpoint,
                                     'email_address': args.email, 'access_token': args.access_token, 'ssl': ssl,
                                     'expires_in': expires_in}
                    logger.info(service_endpoint)
                    folder = ' '.join(args.folder) if args.folder else ''
                    if args.stop:
                        status, message = stop_thread(service_endpoint, folder, auth_method, config_params)
                    elif args.check:
                        status, message = health_check(service_endpoint, folder, auth_method, config_params)
                    elif args.delete:
                        status, message = stop_thread_and_process(service_endpoint, folder,
                                                                  auth_method, config_params)
                    else:
                        trigger = args.trigger
                        if not trigger:
                            raise Exception('Trigger is a mandatory argument')
                        if args.start:
                            status, message = start_thread(service_endpoint, trigger, access_type, exchange, verify_ssl,
                                                           folder, auth_method, expires_in, config_params)
                        else:
                            raise Exception('Unsupported function')
            except Exception as e:
                logger.exception(e)
                message = str(e)
        try:
            clientsocket.sendall(json.dumps({'status': status, 'message': message}).encode('utf-8'))
            clientsocket.close()
        except Exception as e:
            close_connections()
            logger.error("{}".format(e))
        if args.exit:
            if not len(threads):
                logger.debug("No active configuration available. Stopping Notification Service.")
            serversocket.close()
            close_connections()
            time.sleep(DELAY_TIME)
            logger.debug("Notification Service has been successfully stopped.")
            sys.exit()


try:
    PORT = int(sys.argv[1])
    logger.info('starting process on port {}'.format(PORT))
    serversocket.bind(('0.0.0.0', PORT))
except socket.error as msg:
    logger.error('Bind failed: ' + str(msg))
    sys.exit()
serversocket.listen(10)

try:
    while True:
        (clientsocket, address) = serversocket.accept()
        logger.info(clientsocket)
        handle(clientsocket)
except Exception as err:
    logger.error("Listener crashed: {}".format(err))
