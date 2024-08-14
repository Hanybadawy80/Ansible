""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import requests, ast
from datetime import datetime
from urllib.parse import urlparse
from time import ctime, sleep, time
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from exchangelib.protocol import Protocol

Protocol.MAX_SESSION_USAGE_COUNT = 10

if __name__ == 'configuration':
    from exchange_const import (DELAY_TIME, MAX_RETRY, OAUTH_AUTHENTICATION_MAP,
                                TOKEN_URL, SCOPE, DEFAULT_SCOPE, ACCESS_TYPE_MAP)
else:
    from .exchange_const import (DELAY_TIME, MAX_RETRY, OAUTH_AUTHENTICATION_MAP,
                                 TOKEN_URL,
                                 SCOPE, DEFAULT_SCOPE, ACCESS_TYPE_MAP)
from exchangelib import (Account, UTC, Credentials, OAuth2Credentials, Configuration, Identity,
                         OAuth2AuthorizationCodeCredentials, OAUTH2)

CONFIG_SUPPORTS_TOKEN = True
try:
    from connectors.core.utils import update_connnector_config
except:
    CONFIG_SUPPORTS_TOKEN = False

pass_encrypt = True
try:
    from connectors.utils import manage_password
except:
    pass_encrypt = False


class ExchangeConfiguration:
    def __init__(self, config, logger):
        self.exchange = config.get('exchange')
        self.has_ssl = config.get('has_ssl')
        parse_object = urlparse(config.get('host'))
        if parse_object.scheme:
            self.host = parse_object.netloc
        else:
            self.host = parse_object.path
        self.auth_method = config.get('auth_method')
        self.access_type = config.get('access_type')
        self.oauth_auth_type = config.get('access_type')
        self.tenant_id = config.get('tenant_id')
        self.client_id = config.get('client_id')
        self.client_secret = config.get('client_secret')
        self.email_address = config.get('email_address')
        self.code = config.get('code')
        self.username = config.get('username')
        self.password = config.get('password')
        self.access_type = ACCESS_TYPE_MAP.get(
            config.get('access_type')) if self.auth_method == 'OAUTH' else config.get('access_type')
        self.access_type = self.access_type.lower() if self.access_type else 'delegate'
        self.use_autodiscover = config.get('use_autodiscover')
        self.access_token = config.get('access_token')
        self.token_url = TOKEN_URL.format(config.get('tenant_id'))
        self.scope = SCOPE
        self.default_scope = DEFAULT_SCOPE
        self._config = config
        self.logger = logger
        self.verify_ssl = config.get('verify_ssl')
        self.auth_type = OAUTH2 if self.auth_method == 'OAUTH' else None

    def get_credentials(self, connector_info={}):
        if self.auth_method == 'OAUTH':
            return self.get_oauth_credentials(connector_info)
        else:
            return self.get_basic_auth_credentials()

    def get_basic_auth_credentials(self):
        return Credentials(username=self.username, password=self.password)

    def get_oauth2_credentials(self):
        return OAuth2Credentials(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
            identity=Identity(primary_smtp_address=self.email_address)
        )

    def get_oauth_credentials(self, connector_info={}):
        if OAUTH_AUTHENTICATION_MAP.get(self.oauth_auth_type) == 'AUTH_USING_APP':
            return self.get_oauth2_credentials()
        else:
            return self.get_oauth2_authorization_code_credential(connector_info)

    def get_oauth2_authorization_code_credential(self, connector_info={}):
        if self.access_token:
            if connector_info:
                token = self.validate_token(self._config, connector_info)
                access_token = ast.literal_eval(token) if not isinstance(token, dict) else token
                access_token = eval(access_token) if isinstance(access_token, str) else access_token
            else:
                access_token = ast.literal_eval(self.access_token) if not isinstance(self.access_token,
                                                                                     dict) else self.access_token
                access_token = eval(access_token) if isinstance(access_token, str) else access_token

            return OAuth2AuthorizationCodeCredentials(client_id=self.client_id, client_secret=self.client_secret,
                                                      tenant_id=self.tenant_id,
                                                      access_token=access_token)
        elif self.code:
            return OAuth2AuthorizationCodeCredentials(client_id=self.client_id, client_secret=self.client_secret,
                                                      tenant_id=self.tenant_id,
                                                      authorization_code=self.code)
        elif not self.access_token and not self.code:
            raise Exception("At least one parameter access token or code is required")

    def get_exchange_client(self, email, credentials, connector_info={}, read_time_out_retry=True):
        # If the server doesn't support autodiscover, use a Configuration object to set the config
        try:
            retry_count = 0
            while retry_count < MAX_RETRY:
                try:
                    if not self.verify_ssl:
                        BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
                    if self.use_autodiscover:
                        account = Account(primary_smtp_address=email, credentials=credentials,
                                          autodiscover=self.use_autodiscover, access_type=self.access_type.lower(),
                                          default_timezone=UTC)
                    else:
                        config = Configuration(server=self.host, credentials=credentials, auth_type=self.auth_type)
                        account = Account(primary_smtp_address=email, config=config,
                                          access_type=self.access_type.lower(), default_timezone=UTC)
                    oauth_auth_type = OAUTH_AUTHENTICATION_MAP.get(self.oauth_auth_type)
                    if oauth_auth_type == 'AUTH_BEHALF_OF_USER' and account:
                        access_token = account.protocol.credentials.access_token
                        self.update_config(connector_info, access_token)
                    # checking the accessibility of root (this is helpful for access-type is impersonation)
                    if account:
                        root = account.root
                    return account
                except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError,
                        requests.exceptions.ReadTimeout, requests.exceptions.ProxyError, ConnectionResetError) as ex:
                    retry_count += 1
                    if not read_time_out_retry:
                        raise Exception(ex)
                    elif retry_count >= MAX_RETRY:
                        self.logger.error("Retry limit reached: {}".format(retry_count))
                        raise Exception(ex)
                    else:
                        self.logger.error("Retries attempted: {}".format(retry_count))
                        sleep(DELAY_TIME)
        except Exception as err:
            self.logger.exception(str(err))
            raise Exception(str(err))

    def validate_token(self, connector_config, connector_info):
        if CONFIG_SUPPORTS_TOKEN:
            ts_now = time()
            expires = connector_config.get('expires_in')
            expires_ts = ExchangeConfiguration.convert_ts_epoch(expires)
            if ts_now > float(expires_ts):
                self.logger.debug("Token expired at {0}".format(expires))
                access_token = connector_config.get('access_token', {})
                access_token = ast.literal_eval(access_token) if not isinstance(access_token, dict) else access_token
                refresh_token = access_token.get("refresh_token")
                client_id = connector_config.get('client_id')
                client_secret = connector_config.get('client_secret')
                tenant_id = connector_config.get('tenant_id')
                token_resp = ExchangeConfiguration.generate_token(client_id, client_secret, tenant_id, refresh_token,
                                                                  self.verify_ssl)

                self.logger.debug("token successfully regenerated")
                connector_config['access_token'] = manage_password(data=str(token_resp),
                                                                   action='encrypt') if pass_encrypt else str(
                    token_resp)
                connector_config['expires_in'] = (ts_now + token_resp['expires_in']) if token_resp.get(
                    "expires_in") else None
                if connector_info:
                    update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                             connector_config, connector_config['config_id'])
                return token_resp
            else:
                self.logger.debug("Token is valid till {0}".format(expires))
                return connector_config.get('access_token')
        else:
            errmsg = 'update_connnector_config function does not supported for this fortiSOAR version.'
            self.logger.error(errmsg)
            raise Exception(errmsg)

    def update_config(self, connector_info, token_resp):
        if CONFIG_SUPPORTS_TOKEN:
            if not self.access_token:
                ts_now = time()
                self._config['expires_in'] = (ts_now + token_resp['expires_in']) if token_resp.get(
                    "expires_in") else None
                self._config['access_token'] = manage_password(data=str(token_resp),
                                                               action='encrypt') if pass_encrypt else str(token_resp)

                if connector_info:
                    update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                             self._config,
                                             self._config['config_id'])
            else:
                token_resp = self.validate_token(self._config, connector_info)
        else:
            errmsg = 'update_connnector_config function does not supported for this fortiSOAR version.'
            self.logger.error(errmsg)
            raise Exception(errmsg)

    @staticmethod
    def generate_token(client_id, client_secret, tenant_id, refresh_token, verify_ssl):
        payload = {
            'client_id': client_id,
            'client_secret': client_secret
        }
        if refresh_token:
            payload.update({'grant_type': 'refresh_token', 'refresh_token': refresh_token, 'scope': SCOPE})
        else:
            payload.update({'grant_type': 'client_credentials', 'scope': DEFAULT_SCOPE})
        token_url = TOKEN_URL.format(tenant_id)
        response = requests.request("POST", token_url, data=payload, verify=verify_ssl)
        if response.ok:
            return response.json()
        else:
            raise Exception(response.text)

    @staticmethod
    def convert_ts_epoch(ts):
        try:
            datetime_object = datetime.strptime(ctime(ts), '%a %b %d %H:%M:%S %Y')
        except:
            datetime_object = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
        return datetime_object.timestamp()

