""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import base64, copy, re, uuid, requests, time
from os.path import join
from bs4 import BeautifulSoup
from connectors.core.connector import get_logger, ConnectorError
from connectors.cyops_utilities.builtins import download_file_from_cyops
from dateutil import parser
from exchangelib import Message, HTMLBody, FileAttachment, Mailbox, EWSDateTime, EWSTimeZone, Folder, Q
from exchangelib.folders import Messages, DeletedItems, RecoverableItemsDeletions
from integrations.crudhub import make_request, make_file_upload_request
from .emails import explode_email
from .exchange_const import MESSAGES, DEFAULT_FOLDER_PATH, MAX_RETRY, DELAY_TIME, EXTRACT_EMAIL_METADATA_LEGACY, FOLDER_ROOT
from .utils import str_to_list, build_advanced_query
from connectors.environment import expand

logger = get_logger('exchange')


def get_folder_by_name(root, name):
    matching_folders = root.glob('**/{}'.format(name))  # Return sub folders named at any depth
    folders = matching_folders.folders
    if not folders:
        raise ValueError('No subfolders found with name %s' % name)
    if len(folders) > 1:
        raise ValueError('Multiple subfolders found with name %s' % name)
    return folders[0]


def get_folder_name_by_path(client, folder_path):
    folder_path = folder_path.lstrip('/')
    if folder_path.startswith('root/'):
        root_path = client.root
        folders = folder_path.split('/')[1:]
    else:
        root_path = client.msg_folder_root
        folders = folder_path.split('/')
    for f in folders:
        root_path = root_path // f
    return root_path


def _get_exchange_folder(client, folder_name):
    source_list = ['inbox', 'drafts', 'sent', 'trash']
    try:
        if folder_name:
            if folder_name.lower() in source_list:
                return getattr(client, folder_name.lower())
            elif '/' in folder_name:
                return get_folder_name_by_path(client, folder_name)
            else:
                return get_folder_by_name(client.root, folder_name)
        else:
            return client.inbox
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _add_attachment_to_email(iri, iri_type, inline=False):
    try:
        file_name = None
        if iri_type == 'attachment':
            attachment_data = make_request(iri, 'GET')
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
        else:
            file_iri = iri
        file_download_response = download_file_from_cyops(file_iri)
        if not file_name:
            file_name = file_download_response['filename']
        file_path = join('/tmp', file_download_response['cyops_file_path'])
        with open(file_path, 'rb') as attachment:
            file_data = attachment.read()
        if inline:
            my_file = FileAttachment(name=file_name, content=file_data, is_inline=True, content_id=iri.split("/")[-1])
        else:
            my_file = FileAttachment(name=file_name, content=file_data)
        return my_file
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(MESSAGES.get('attachment_not_found').format(str(iri)))


def _get_list_of_ids(list_ids):
    try:
        result = []
        list_ids = str_to_list(list_ids)
        for id in list_ids:
            res = Mailbox(email_address=id.strip())
            result.append(res)
        return result
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def _handle_attachments(iri_list, msg, inline=False):
    for iri in iri_list:
        iri_type = 'attachment'
        if not iri.startswith('/api/3/'):
            iri = '/api/3/attachments/' + iri
        elif iri.startswith('/api/3/files'):
            iri_type = 'file'
        my_file = _add_attachment_to_email(iri, iri_type, inline)
        msg.attach(my_file)
        logger.debug(MESSAGES.get('attachment_iri').format(iri))


def parse_and_replace_image(email_body):
    soup = BeautifulSoup(email_body, 'html.parser')
    image_content = []
    for img in soup.findAll('img'):
        image_content.append(img.get('src', ''))
    inline_attachments = []
    for encoded_image in image_content:
        if 'data:image' in encoded_image:
            file_name = uuid.uuid4().hex
            body_content = encoded_image.split(' ')[0]
            body_content_copy = copy.deepcopy(body_content)
            file_extension = body_content_copy.split(';')[0].split('/')[1]
            body_content = re.sub("data:image/.*;base64,", "", body_content)
            body_content = base64.b64decode(body_content)
            my_file = FileAttachment(name=file_name + '.' + file_extension, content=body_content, is_inline=True,
                                     content_id=file_name)
            inline_attachments.append(my_file)
            email_body = email_body.replace(body_content_copy, "cid:" + file_name)
            email_body = email_body.replace("\n", "")
    email_body_with_id = email_body, inline_attachments
    return email_body_with_id


def _email_template_handler(params, env={}):
    email_template = params.get('email_templates')
    request_body = {'logic': 'OR', 'filters': [{'field': 'name', 'operator': 'eq', 'value': email_template}]}
    response = make_request('/api/query/email_templates', 'POST', body=request_body)['hydra:member']
    subject = ''
    content = ''
    if response:
        subject = response[0]['subject']
        content = response[0]['content']
        try:
            subject = expand(env, subject)
            content = expand(env, content)
        except Exception as err:
            raise ConnectorError(err)
    return subject, content


def send_email(client, params, **kwargs):
    try:
        retry_count = 0
        to_id_list = _get_list_of_ids(params.get('to_recipients'))
        cc_id_list = _get_list_of_ids(params.get('cc_recipients'))
        bcc_id_list = _get_list_of_ids(params.get('bcc_recipients'))
        if not to_id_list and not cc_id_list and not bcc_id_list:
            logger.exception(MESSAGES.get('required_to_bcc_cc'))
            raise ConnectorError(MESSAGES.get('required_to_bcc_cc'))
        if params.get('body_type') == 'Email Template':
            subject, body = _email_template_handler(params, kwargs.get('env', {}))
        else:
            body = params.get('body')
            subject = str(params.get('subject'))
        parsed_body, inline_attachments = parse_and_replace_image(body)
        while retry_count < MAX_RETRY:
            try:
                msg = Message(
                    account=client,
                    subject=subject,
                    folder=client.sent,
                    body=HTMLBody(parsed_body.strip('"')),
                    to_recipients=to_id_list,
                    cc_recipients=cc_id_list,
                    bcc_recipients=bcc_id_list,
                )
                logger.debug('message object created successfully')
                _handle_attachments(str_to_list(params.get('iri_list')), msg)
                _handle_attachments(str_to_list(params.get('inline_iri_list')), msg, True)
                for attachment in inline_attachments:
                    msg.attach(attachment)
                result = msg.send_and_save()
                logger.debug(MESSAGES.get('send_resp'))
                return {"message": MESSAGES.get('send_resp')}

            except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError,
                    requests.exceptions.ProxyError) as ex:
                retry_count += 1
                if retry_count >= MAX_RETRY:
                    logger.error("Retry limit reached: {}".format(retry_count))
                    raise ConnectorError(ex)
                else:
                    logger.error("Retries attempted: {}".format(retry_count))
                    time.sleep(DELAY_TIME)

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def upload_file_to_cyops(file_name, file_content, file_type=None, description=None):
    try:
        response = make_file_upload_request(file_name, file_content, file_type)
        file_id = response['@id']
        file_description = description if description else 'Email file as attachment'
        attach_response = make_request('/api/3/attachments', 'POST',
                                       {'name': file_name, 'file': file_id,
                                        'description': file_description})
        return attach_response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def process_email_data(unread_emails, params, folder_path, updated_headers, **kwargs):
    try:
        emails = []
        has_attachments = False
        parse_inline = params.get('parse_inline')
        mark_read = params.get('mark_read')
        save_as_attachment = params.get('save_as_attachment')
        extract_attach_data = params.get('extract_attach_data')

        pull_oldest = params.get('pull_oldest')
        if pull_oldest:
            unread_emails = unread_emails.order_by('datetime_received')

        limit = params.get('limit')
        if limit:
            unread_emails = unread_emails[:limit]

        for email in unread_emails:
            try:
                has_attachments = email.has_attachments
                raw_msg = email.mime_content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                raw_msg = email.mime_content.decode('cp1252')
            if mark_read:
                email.is_read = True
                email.save(update_fields=['is_read'])

                # extracting email content
            parsed_email = explode_email(raw_msg, parse_inline, extract_attach_data, updated_headers, has_attachments=has_attachments, **kwargs)
            parsed_email.update({'folder_path': folder_path})
            parsed_email['item_id'] = email.id
            if save_as_attachment:
                subject = parsed_email.get('headers', {}).get('subject')
                attach_response = upload_file_to_cyops('email_as_attch.eml', raw_msg, description=subject)
                parsed_email['email_as_attachment'] = attach_response
            if parsed_email['raw']:
                parsed_email.pop('raw')
            emails.append(parsed_email)
        return emails
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_folders(account):
    folders = []
    for path in DEFAULT_FOLDER_PATH:
        root_path = account.root // path
        for folder in root_path.walk():
            if isinstance(folder, Messages):
                folders.append(folder)
            if isinstance(folder, DeletedItems):
                folders.append(folder)
            if isinstance(folder, RecoverableItemsDeletions):
                folders.append(folder)
    return folders


def fetch_unread_email(client, params, updated_headers=False, **kwargs):
    emails = []
    folders = get_mailbox_folders(client, params)
    exclude_absolute_path = params.get('exclude_absolute_path')
    kwargs['get_parsed_images'] = True
    for folder in folders:
        unread_emails = folder.filter(is_read=False)
        if unread_emails.folder_collection.folders[0].unread_count:
            if exclude_absolute_path:
                folder_path = folder.name
            else:
                folder_path = folder.absolute
            emails.extend(process_email_data(unread_emails, params, folder_path, updated_headers, **kwargs))
    return emails


def get_email_new(client, params, **kwargs):
    return fetch_unread_email(client, params, updated_headers=True, **kwargs)


def get_email(client, params, **kwargs):
    return fetch_unread_email(client, params, **kwargs)


def get_folder_by_path(client, source_dest, folder_path, folder_name):
    if source_dest == 'Folder Path':
        folders = [f for f in folder_path.split('/')[2:]]
        folder = client.root
        if folders:
            for f in folders:
                folder = folder // f
        else:
            folder = get_folder_by_name(folder, source_dest)
        return folder
    else:
        folder = _get_exchange_folder(client, folder_name)
    return folder


def move_email(dest_client, params, src_client, admin_email, **kwargs):
    return copy_move_email(dest_client, params, src_client, admin_email, action='move')


def copy_email(dest_client, params, src_client, admin_email, **kwargs):
    return copy_move_email(dest_client, params, src_client, admin_email, action='copy')


def copy_move_email(dest_client, params, src_client, admin_email, action):
    try:
        source = params.get('source')
        source_folder_path = params.get('source_folder_path')
        source_folder = params.get('source_folder')
        src_folder = get_folder_by_path(src_client, source, source_folder_path, source_folder)
        destination = params.get('destination')
        destination_folder_path = params.get('destination_folder_path')
        dest_folder = params.get('dest_folder')
        destination_folder = get_folder_by_path(dest_client, destination, destination_folder_path, dest_folder)
        message_id = params.get('message_id').strip()
        for email in src_folder.filter(message_id=message_id):
            try:
                if dest_client.access_type == 'delegate':
                    if action == 'move':
                        email.move(destination_folder)
                    if action == 'copy':
                        email.copy(destination_folder)
                else:
                    exported_items = src_client.export([email])
                    dest_client.upload([(destination_folder, exported_items[0])])
                    if action == 'move':
                        src_client.bulk_delete([email])
            except AssertionError as e:
                if not e:
                    raise e
            logger.debug(MESSAGES.get('move_resp') if action == 'move' else MESSAGES.get('copy_resp'))
            dest_folder = dest_folder if dest_folder else destination_folder_path
            res = MESSAGES.get('moved_status').format(dest_folder) if action == 'move' else MESSAGES.get(
                'copy_status').format(dest_folder)
            return res
        logger.warn(MESSAGES.get('invalid_input'))
        return {"message": MESSAGES.get('invalid_input')}

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def parse_query_result(src, qs, pull_oldest, limit, parse_inline, extract_attach_data, exclude_absolute_path, save_as_attachment=False, **kwargs):
    emails = []
    qs = qs.order_by('datetime_received') if pull_oldest else qs
    qs = qs[:limit] if limit else qs
    for email in qs:
        raw_msg = email.mime_content.decode('utf-8', errors='ignore')
        has_attachments = email.has_attachments
        parsed_email = explode_email(raw_msg, parse_inline, extract_attach_data,
                                     updated_headers=EXTRACT_EMAIL_METADATA_LEGACY, has_attachments=has_attachments, **kwargs)
        parsed_email['item_id'] = email.id
        if save_as_attachment:
            subject = parsed_email.get('headers', {}).get('Subject')
            attach_response = upload_file_to_cyops('email_as_attch.eml', raw_msg, description=subject)
            parsed_email['email_as_attachment'] = attach_response
        if exclude_absolute_path:
            parsed_email['folder_path'] = src.name
        else:
            parsed_email['folder_path'] = src.absolute
        if parsed_email['raw']:
            parsed_email.pop('raw')
        emails.append(parsed_email)
    return emails


def run_query(client, params, **kwargs):
    try:
        emails = []
        mailbox_folder = []
        search_fields = ''
        parse_inline = params.get('parse_inline')
        kwargs['get_parsed_images'] = True
        extract_attach_data = params.get('extract_attach_data')
        folder = params.get('folder')
        pull_oldest = params.get('pull_oldest')
        save_as_attachment = params.get('save_as_attachment')
        limit = params.get('range')
        exclude_absolute_path = params.get('exclude_absolute_path')
        query_method = params.get('query_method')
        query_object = None
        query_string = {}
        if query_method == 'Advanced':
            advanced_query = params.pop('advanced_query')
            if advanced_query:
                query_object = build_advanced_query(advanced_query, client)
                logger.debug("Advanced Query : {0}".format(str(query_object)))
        else:
            subject = params.get('subject_text')
            body = params.get('body_text')
            sender = params.get('sender_text')
            query_string = {
                'sender__icontains': sender,
                'subject__icontains': str(subject),
                'body__icontains': body
            }
            query_string = {k: v for k, v in query_string.items() if v}
            query = params.get('query')
            if query:
                if not isinstance(query, dict):
                    logger.error(MESSAGES.get('invalid_json'))
                    raise ConnectorError(MESSAGES.get('invalid_json'))
                if 'datetime_received__gt' in query.keys():
                    tz = EWSTimeZone.localzone()
                    dt_obj = parser.parse(query['datetime_received__gt'])
                    localized_dt = EWSDateTime.from_datetime(dt_obj).astimezone(tz)
                    query['datetime_received__gt'] = localized_dt
                query_string.update(query)
        if folder.lower() == 'all':
            mailbox_folder = get_folders(client)
        else:
            mailbox_folder.append(_get_exchange_folder(client, folder))
        search_fields += '{},'.format(folder if folder else 'inbox')
        for folder in mailbox_folder:
            if query_string:
                qs = folder.filter(**query_string)
            elif query_object:
                qs = folder.filter(query_object)
            else:
                qs = folder.all()
            if qs.count():
                emails.extend(parse_query_result(folder, qs, pull_oldest, limit, parse_inline,
                                                 extract_attach_data, exclude_absolute_path, save_as_attachment, **kwargs))
        email = {'emails': emails, 'search_fields': search_fields}
        return email

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def send_reply(client, params, **kwrgs):
    try:
        message_id = params.get("message_id")
        folder = params.get("folder_name")
        subject = params.get("subject")
        to_recipients = str_to_list(params.get('to_recipients'))
        parsed_body, inline_attachments = parse_and_replace_image(params.get('body'))
        body = HTMLBody(parsed_body.strip('"'))
        msg = get_email_by_message_id(client, folder, message_id.strip())
        if msg:
            to_recipients.append(msg.sender.email_address)
            if not subject:
                if not subject.startswith("Re:"):
                    subject = "Re: " + msg.conversation_topic
                else:
                    subject = msg.conversation_topic
            elif not subject.startswith("Re:"):
                subject = "Re: " + subject
            if params.get('reply_all'):
                msg.reply_all(subject=subject, body=body)
            else:
                msg.reply(subject=subject, body=body, to_recipients=to_recipients)
            logger.debug(MESSAGES.get('send_resp'))
            return {"message": MESSAGES.get('send_resp')}
        else:
            return {"message": MESSAGES.get('invalid_input')}
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(str(e))


def get_email_by_message_id(client, folder_name, message_id):
    try:
        if folder_name:
            src = _get_exchange_folder(client, folder_name)
            for email in src.filter(message_id=message_id):
                return email
        else:
            root_path = client.root // DEFAULT_FOLDER_PATH[0]
            for folder in root_path.walk():
                if isinstance(folder, Messages):
                    for email in folder.filter(message_id=message_id):
                        return email
            return None
    except Exception as e:
        logger.exception(e)
        raise ConnectorError(e)


def _mark_as_read(email):
    try:
        email.is_read = True
        email.save(update_fields=['is_read'])
        logger.debug(MESSAGES.get('marked_read'))
        return {"message": MESSAGES.get('marked_read')}
    except Exception as e:
        logger.exception(str(e))
        raise ConnectorError(str(e))


def _delete_email(delete_type, email):
    try:
        if delete_type == 'Move To Trash':
            email.move_to_trash()
        elif delete_type == 'Hard Delete':
            email.delete()
        elif delete_type == 'Soft Delete':
            email.soft_delete()
        return {"message": MESSAGES.get('delete_resp')}
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def perform_action(client, params, action):
    try:
        message_id = params.get('message_id').strip()
        folder_name = params.get('folder_name')
        email = get_email_by_message_id(client, folder_name, message_id)
        if email:
            if action.lower() == 'delete':
                delete_type = params.get('delete_type')
                return _delete_email(delete_type, email)
            else:
                return _mark_as_read(email)
        else:
            return {"message": MESSAGES.get('not_found')}
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def delete_email(client, params, **kwargs):
    return perform_action(client, params, action='delete')


def mark_as_read(client, params, **kwargs):
    return perform_action(client, params, action='read')


def get_folder_meta_info(src_folder, prev_resp):
    refresh = src_folder.refresh()
    resp = {
        'folder': src_folder.name,
        'total_email_count': src_folder.total_count,
        'unread_email_count': src_folder.unread_count,
        'child_folder_count': src_folder.child_folder_count,
        'child_folder_metadata': []
    }
    result = dict()
    if prev_resp:
        prev_resp.get('child_folder_metadata').append(resp)
    child_folder_count = src_folder.child_folder_count
    if child_folder_count:
        child_folders = src_folder.children
        for folder in child_folders:
            result.update(resp)
            get_folder_meta_info(folder, result)
    else:
        return resp
    return resp


def get_folder_metadata(account, params, **kwargs):
    try:
        folder_name = params.get('source')
        if folder_name == 'Custom Folder':
            folder_name = params.get('source_folder')
        src_folder = _get_exchange_folder(account, folder_name)
        return get_folder_meta_info(src_folder, {})

    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_mailbox_folders(account, params):
    source = params.get('source')
    if source.lower() == 'all':
        src_folder = get_folders(account)
    else:
        folder_name = params.get('source')
        if folder_name == 'Custom Folder':
            folder_name = params.get('source_folder')
        src_folder = [_get_exchange_folder(account, folder_name)]
    return src_folder


def get_category(account, params, **kwargs):
    message_id = params.get('message_id').strip()
    response = {'status': 'success', 'message': MESSAGES.get('not_found'), 'message_id': message_id}
    src_folder = get_mailbox_folders(account, params)
    for folder in src_folder:
        for email in folder.filter(message_id=message_id):
            categories = email.categories
            response.update(
                {'message': MESSAGES.get('fetch_category'), 'categories': categories, 'subject': email.subject})
            return response
    return response


def add_category(account, params, **kwargs):
    categories = params.get('categories')
    category = []
    if categories and isinstance(categories, str):
        category = categories.split(',')
        category = [category_tmp.strip() for category_tmp in category]
    else:
        category.extend(categories)
    message_id = params.get('message_id').strip()
    response = {'status': 'success', 'message': MESSAGES.get('not_found'), 'message_id': message_id}
    src_folder = get_mailbox_folders(account, params)
    for folder in src_folder:
        for email in folder.filter(message_id=message_id):
            existing_category = email.categories
            if existing_category:
                category.extend(existing_category)
            email.categories = category
            email.save()
            response.update(
                {'message': MESSAGES.get('add_category'), 'categories': categories, 'subject': email.subject})
            return response
    return response


def remove_category(account, params, **kwargs):
    message_id = params.get('message_id').strip()
    response = {'status': 'success', 'message': MESSAGES.get('not_found'), 'message_id': message_id}
    categories = params.get('categories')
    if categories and isinstance(categories, str):
        categories = categories.split(',')
        categories = [category.strip() for category in categories]
    src_folder = get_mailbox_folders(account, params)
    not_found = []
    found = []
    for folder in src_folder:
        for email in folder.filter(message_id=message_id):
            existing_category = email.categories
            [not_found.append(category) if category not in existing_category else found.append(category) for category in
             categories]
            [existing_category.remove(category) for category in categories if category in existing_category]
            email.categories = existing_category
            email.save()
            response.update({'message': MESSAGES.get('remove_category'), 'removed': found, 'not_found': not_found,
                             'subject': email.subject})
            return response
    return response


def create_folder(client, params, **kwargs):
    parent_folder_path = params.get('parent_folder_path')
    new_folder_name = params.get('folder_name')
    if not parent_folder_path:
        parent_folder_path = f'/{FOLDER_ROOT}/{DEFAULT_FOLDER_PATH[0]}'
    full_path = f'{parent_folder_path}/{new_folder_name}'
    result = {'status': '', 'message': '', 'folder_absolute_path': '', 'folder_creation_status':''}
    try:
        folder_path = get_folder_name_by_path(client, full_path)
        if folder_path:
            result.update({'status': 'success', 'folder_creation_status': False,
                           'message': f"Folder '{new_folder_name}' already exists", 'folder_absolute_path': full_path})
            return result
    except Exception as err:
        pass
    parent_folder = get_folder_name_by_path(client, parent_folder_path)
    f = Folder(parent=parent_folder, name=new_folder_name)
    f.save()
    get_folder_name_by_path(client, full_path)
    result.update({'status': 'success', 'folder_creation_status': True,
                   'message': f"Folder '{new_folder_name}' created successfully", 'folder_absolute_path': f.absolute})
    return result
