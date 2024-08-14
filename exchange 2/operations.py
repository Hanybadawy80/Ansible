""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import base64
import vobject
from connectors.core.connector import get_logger, ConnectorError
from .calendar_operations import get_calendar_events, create_calendar_event
from .email_operations import (get_email, send_email, mark_as_read, move_email, delete_email, run_query, get_email_new,
                               get_folder_metadata, add_category, get_category, remove_category, copy_email, send_reply,
                               create_folder)
from integrations.crudhub import make_request

logger = get_logger('exchange')

CONFIG_SUPPORTS_TOKEN = True
try:
    from connectors.core.utils import update_connnector_config
except:
    CONFIG_SUPPORTS_TOKEN = False


def get_contacts(client, params, **kwargs):
    try:
        contact_dict = {}
        contact_list = []
        for item in client.contacts.all():
            raw_msg = item.mime_content.decode('utf-8')
            vcard = vobject.readOne(raw_msg)
            for contact_obj in vcard.getChildren():
                name = contact_obj.name
                value = contact_obj.value
                contact_dict[name] = str(value)
            contact_list.append(contact_dict)
        return contact_list
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_email_templates():
    email_template_names = []
    response = make_request('/api/3/email_templates', 'GET')['hydra:member']
    for email_template in response:
        email_template_names.append(email_template['name'])
    return email_template_names


operations = {
    'get_email_new': get_email_new,
    'get_email': get_email,
    'delete_email': delete_email,
    'run_query': run_query,
    'move_email': move_email,
    'copy_email': copy_email,
    'send_email': send_email,
    'send_email_new': send_email,
    'get_contacts': get_contacts,
    'mark_as_read': mark_as_read,
    'get_calendar_events': get_calendar_events,
    'create_calendar_event': create_calendar_event,
    'get_folder_metadata': get_folder_metadata,
    'get_category': get_category,
    'add_category': add_category,
    'remove_category': remove_category,
    'send_reply': send_reply,
    'create_folder': create_folder,
    'get_email_templates': get_email_templates
}
