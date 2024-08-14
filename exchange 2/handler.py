""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json, logging, os, socket, subprocess, sys, time
from connectors.core.connector import ConnectorError
from .exchange_const import DEFAULT_PORT, AUTH_TYPE, OAUTH_AUTHENTICATION_MAP

listener_path = os.path.join(os.path.dirname(__file__), 'scripts/notify_email.py')
logger = logging.getLogger(__name__)
LISTENER_HOST = 'localhost'


def send_socket_message(message, listener_port):
    try:
        validate_listener_port(listener_port)
    except:
        pass
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((LISTENER_HOST, listener_port))
    client.sendall(message.encode('utf-8'))
    response = client.recv(4096)
    client.close()
    if response:
        response_json = json.loads(response.decode('utf-8'))
        logger.info('response status: {}'.format(response_json['status']))
        status = response_json['status']
        if status != 0:
            logger.error("{}".format(response_json['message']))
            raise ConnectorError(response_json['message'])
        else:
            return response_json


def check_listener_status(listener_port):
    try:
        ps = subprocess.Popen(('netstat', '-anp'), stdout=subprocess.PIPE)
        output = subprocess.check_output(('grep', '{}'.format(listener_port)), stdin=ps.stdout).decode("utf-8")
        if "LISTEN" not in output:
            logger.error("netstat output: {}".format(output))
    except Exception as err:
        logger.warn(err)


def validate_listener_port(listener_port):
    args = ['/usr/sbin/lsof', '-titcp:' + str(listener_port)]
    pid = subprocess.check_output(args=args, shell=False).decode("utf-8")
    logger.info("PID: {}".format(pid))
    pids = pid.strip('\n').split('\n')
    path_found = False
    cmd_out = ''
    for pid in pids:
        if pid:
            check_listener_status(listener_port)
        args = ['ps', '-f', '-o', 'cmd', '-p', pid.strip('\n')]
        cmd_out = subprocess.check_output(args=args, shell=False).decode("utf-8")
        list_cmd_out = cmd_out.split(' ')
        for path in list_cmd_out:
            if listener_path.strip('.') in path.strip('.') or path.strip('.') in listener_path.strip('.'):
                path_found = True
                break
    if not path_found:
        raise subprocess.CalledProcessError(returncode=-1, cmd=cmd_out, output='Port already in use.')


class ConfigHandler:
    def __init__(self, config={}):
        try:
            import uwsgi
            self._python_path = uwsgi.opt['virtualenv'].decode('utf-8') + '/bin/python'
        except Exception:
            # when run locally
            self._python_path = str(sys.executable)
        self._config = config
        self._listener_port = config.get('port', DEFAULT_PORT)
        self.access_token = json.dumps(config.get('access_token', '')).replace(' ', '')
        self._listener_mailbox = config.get('mailbox', 'inbox')
        self.auth_method = AUTH_TYPE.get(self._config.get('auth_method'))
        self.access_type = OAUTH_AUTHENTICATION_MAP.get(
            self._config.get('access_type')) if self.auth_method == 'OAUTH' else self._config.get('access_type')

    def start_listener_socket(self):
        try:
            validate_listener_port(self._listener_port)
        except subprocess.CalledProcessError as e:
            logger.info('Socket listener is not up. Starting...')
            subprocess.Popen([self._python_path, listener_path, str(self._listener_port)])
            # wait for 5 seconds
            time.sleep(5)
            try:
                validate_listener_port(self._listener_port)
            except subprocess.CalledProcessError as e2:
                msg = "Error in bringing up notification service"
                logger.error(msg)
                raise ConnectorError("Error starting listener: {}".format(e2))

    def start_listener(self):
        self.start_listener_socket()
        logger.info('in start listener action')
        return send_socket_message(
            '--start --host {0} --username {1} --password {2} --ssl {3} --email {4} --folder {5} --accessType {6} --trigger {7} --exchange {8} --verify_ssl {9}'
            ' --client_id {10} --client_secret {11} --tenant_id {12} --auth_method {13} --access_token {14} --expires_in {15}'.format(
                self._config.get('host'), self._config.get('username'), self._config.get('password'),
                self._config.get('has_ssl'), self._config.get('email_address'), self._listener_mailbox,
                self.access_type,
                self._config.get('trigger'), self._config.get('exchange'), self._config.get('verify_ssl'),
                self._config.get('client_id'),
                self._config.get('client_secret'), self._config.get('tenant_id'), self.auth_method, self.access_token,
                self._config.get('expires_in')), self._listener_port)

    def stop_listener(self):
        try:
            return send_socket_message(
                '--stop --host {0} --username {1} --email {2} --folder {3} --client_id {4} --tenant_id {5} --auth_method {6} --accessType {7}'.format(
                    self._config.get('host'), self._config.get('username'), self._config.get('email_address'),
                    self._listener_mailbox, self._config.get('client_id'),
                    self._config.get('tenant_id'), self.auth_method,
                    self.access_type), self._listener_port)
        except ConnectionRefusedError:
            logger.warning('Listener is in Stopped state. Returning. Deactivate and activate the '
                           'connector to restart the listeners')

    def exit_socket(self):
        try:
            return send_socket_message('--exit', self._listener_port)
        except ConnectionRefusedError:
            logger.warning(
                'Listener is in Stopped state. Returning. Deactivate and activate the connector to restart the '
                'listeners')
            return 'Success'

    def closed_socket_connection(self):
        try:
            return send_socket_message('--delete --host {0} --username {1} --email {2} --folder {3} --client_id {4} '
                                       ' --tenant_id {5} --auth_method {6} --accessType {7}'.format(
                self._config.get('host'), self._config.get('username'), self._config.get('email_address'),
                self._listener_mailbox, self._config.get('client_id'), self._config.get('tenant_id'),
                self.auth_method, self.access_type), self._listener_port)
        except ConnectionRefusedError:
            logger.warning(
                'Listener is in Stopped state. Returning. Deactivate and activate the connector to restart the '
                'listeners')
            return 'Success'

    def check_listener_health(self):
        try:
            logger.info("sending message for health check")
            self.start_listener_socket()
            return send_socket_message(
                '--check --host {0} --username {1} --password {2} --ssl {3} --email {4} --folder {5} --verify_ssl {6} --client_id {7} '
                '--client_secret {8} --tenant_id {9} --auth_method {10} --accessType {11} --access_token {12} --expires_in {13}'.format(
                    self._config.get('host'), self._config.get('username'), self._config.get('password'),
                    self._config.get('has_ssl'), self._config.get('email_address'), self._listener_mailbox,
                    self._config.get('verify_ssl'), self._config.get('client_id'),
                    self._config.get('client_secret'), self._config.get('tenant_id'),
                    self.auth_method, self.access_type, self.access_token,
                    self._config.get('expires_in')), self._listener_port)
        except ConnectionRefusedError:
            logger.warning('Listener is in Stopped state. Returning')
            raise ConnectorError('Listener is in Stopped state. Deactivate and activate the connector to restart the '
                                 'listeners')

