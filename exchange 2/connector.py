""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import time
from connectors.core.connector import Connector, ConnectorError
from .builtins import *
from .operations import operations
from .exchange_const import DEFAULT_PORT, OAUTH_AUTHENTICATION_MAP
from .configuration import ExchangeConfiguration
try:
    from connectors.core.utils import get_existing_test_configurations
except:
    pass

pass_encrypt = True
try:
    from connectors.utils import manage_password
except:
    pass_encrypt = False

CONFIG_SUPPORTS_TOKEN = True
try:
    from connectors.core.utils import update_connnector_config
except:
    CONFIG_SUPPORTS_TOKEN = False

logger = get_logger('exchange')


class Exchange(Connector):
    def execute(self, config, operation, params, **kwargs):
        action = operations.get(operation)
        logger.debug('Executing operation {}'.format(action))
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}
        if operation == 'get_email_templates':
            return action()

        try:
            if pass_encrypt:
                if config.get('password'):
                    config['password'] = manage_password(config.get('password'), 'decrypt')
                if config.get('client_secret'):
                    config['client_secret'] = manage_password(config.get('client_secret'), 'decrypt')
            config_obj = ExchangeConfiguration(config, logger)
            email = config_obj.email_address
            credentials = config_obj.get_credentials(connector_info)
            if operation == 'move_email' or operation == 'copy_email':
                target_email = params.get('target_email') if params.get('target_email') else email
                dest_client = config_obj.get_exchange_client(target_email, credentials, connector_info)
                src_email = params.get('source_email') if params.get('source_email') else email
                src_client = config_obj.get_exchange_client(src_email, credentials, connector_info)
                resp = action(dest_client, params, src_client, email, **kwargs)
                src_client.protocol.close()
                dest_client.protocol.close()
            elif operation == 'delete_email' or operation == 'run_query' or operation == 'create_folder':
                target_email = params.get('target_email') if params.get('target_email') else email
                target_client = config_obj.get_exchange_client(target_email, credentials, connector_info)
                resp = action(target_client, params, **kwargs)
                target_client.protocol.close()
            else:
                client = config_obj.get_exchange_client(email, credentials, connector_info)
                resp = action(client, params, **kwargs)
                client.protocol.close()
            return resp
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    def on_add_config(self, config, active):
        connector_info = {
            "connector_name": self._info_json.get('name'),
            "connector_version": self._info_json.get('version')}
        if pass_encrypt:
            if config.get('password'):
                config['password'] = manage_password(config.get('password'), 'decrypt')
            if config.get('client_secret'):
                config['client_secret'] = manage_password(config.get('client_secret'), 'decrypt')

        if active and config.get('notification_service'):
            try:
                start_notification(config)
                Exchange.deactivate_test_config(config, connector_info)
            except Exception as e:
                logger.exception(e)

    def on_app_start(self, config, active):
        connector_info = {
            "connector_name": self._info_json.get('name'),
            "connector_version": self._info_json.get('version')}
        if active:
            config_list = list(config.values())
            for each_config in config_list:
                if each_config.get('notification_service'):
                    try:
                        if OAUTH_AUTHENTICATION_MAP.get(each_config.get('access_type', '')) == 'AUTH_BEHALF_OF_USER':
                            config_obj = ExchangeConfiguration(config, logger)
                            config_obj.validate_token(each_config, connector_info)
                        start_notification(each_config)
                        Exchange.deactivate_test_config(config, connector_info)
                    except Exception as e:
                        logger.error("on app start", e)

    def on_activate(self, config):
        connector_info = {
            "connector_name": self._info_json.get('name'),
            "connector_version": self._info_json.get('version')}
        for conf in config.values():
            if conf.get('notification_service'):
                try:
                    if OAUTH_AUTHENTICATION_MAP.get(conf.get('access_type', '')) == 'AUTH_BEHALF_OF_USER':
                        config_obj = ExchangeConfiguration(config, logger)
                        config_obj.validate_token(conf, connector_info)
                    start_notification(conf)
                    Exchange.deactivate_test_config(config, connector_info)
                except Exception as e:
                    logger.info(e)

    def on_delete_config(self, config):
        if config.get('notification_service'):
            closed_connection(config)

    def on_update_config(self, old_config, new_config, active):
        connector_info = {"connector_name": self._info_json.get('name'),
                          "connector_version": self._info_json.get('version')}
        if pass_encrypt:
            if new_config.get('password'):
                new_config['password'] = manage_password(new_config.get('password'), 'decrypt')
            if new_config.get('client_secret'):
                new_config['client_secret'] = manage_password(new_config.get('client_secret'), 'decrypt')
        if OAUTH_AUTHENTICATION_MAP.get(new_config.get('access_type', '')) == 'AUTH_BEHALF_OF_USER':
            old_config_code = old_config.get('code')
            new_config_code = new_config.get('code')
            if old_config_code != new_config_code:
                new_config['access_token'] = {}
            else:
                expires_in = old_config.get('expires_in')
                if not expires_in:
                    new_config['expires_in'] = expires_in if expires_in else old_config.get('access_token', {}).get(
                        'expires_at')
                else:
                    new_config['expires_in'] = expires_in
                new_config['access_token'] = old_config.get('access_token')
                update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                         new_config,
                                         new_config['config_id'])
        if old_config.get('notification_service'):
            stop_notification(old_config)
        if active and new_config.get('notification_service'):
            time.sleep(5)
            try:
                start_notification(new_config)
                Exchange.deactivate_test_config(new_config, connector_info)
            except Exception as e:
                logger.exception(e)

    def on_deactivate(self, config):
        visited_ports = []
        for conf in config.values():
            try:
                if conf.get('notification_service') and not conf.get('port', DEFAULT_PORT) in visited_ports:
                    visited_ports.append(conf.get('port', DEFAULT_PORT))
                    exit_notifier(conf)
            except Exception as e:
                logger.error(e)

    def teardown(self, config):
        logger.debug('on teardown')
        self.on_deactivate(config)

    def check_health(self, config):
        try:
            if config.get("exchange"):
                config["exchange"] = config["exchange"].replace(" ", "")
            logger.info('executing check health')
            if pass_encrypt:
                if config.get('password'):
                    config['password'] = manage_password(config.get('password'), 'decrypt')
                if config.get('client_secret'):
                    config['client_secret'] = manage_password(config.get('client_secret'), 'decrypt')
            connector_info = {"connector_name": self._info_json.get('name'),
                              "connector_version": self._info_json.get('version')}
            config_obj = ExchangeConfiguration(config, logger)
            email = config_obj.email_address
            credentials = config_obj.get_credentials(connector_info)
            client = config_obj.get_exchange_client(email, credentials, read_time_out_retry=False, connector_info=connector_info)
            client.protocol.close()
            if config.get('notification_service'):
                logger.info('checking health of notification service')
                try:
                    config['refresh_config_flag'] = True
                    check_listener_health(config)
                except Exception as e:
                    logger.exception(e)
                    raise ConnectorError(e)
            return True
        except Exception as err:
            logger.exception(str(err))
            raise ConnectorError(str(err))

    @staticmethod
    # Deactivates listeners activated for the test configuration  created during development of the connector using BYOC
    def deactivate_test_config(config, connector_info):
        try:
            all_config = get_existing_test_configurations(config)
            for test_config in all_config:
                if test_config.get('notification_service'):
                    stop_notification(test_config)
                    test_config["notification_service"] = False
                    update_connnector_config(connector_info['connector_name'], connector_info['connector_version'],
                                             test_config, test_config.get("config_id"))
        except Exception as error:
            logger.error('Error occurred while deactivate test config listeners: {0}'.format(error))
