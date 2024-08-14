""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
"""
Steps related to fetching and parsing email
"""

from connectors.core.connector import get_logger
from .handler import ConfigHandler

logger = get_logger("exchange")


def start_notification(config, *args, **kwargs):
    return ConfigHandler(config).start_listener()


def stop_notification(config):
    return ConfigHandler(config).stop_listener()


def check_listener_health(config):
    return ConfigHandler(config).check_listener_health()


def closed_connection(config):
    return ConfigHandler(config).closed_socket_connection()


def exit_notifier(config={}):
    return ConfigHandler(config).exit_socket()

