""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
from exchangelib import HTMLBody, CalendarItem, EWSDateTime, EWSTimeZone
from exchangelib.items import SEND_ONLY_TO_ALL
from dateutil import parser
from connectors.core.connector import get_logger, ConnectorError
from .utils import str_to_list
from .exchange_const import minutes_dict

logger = get_logger('exchange')


def _datetime_conversion(date_time):
    try:
        tz = EWSTimeZone.localzone()
        dt_obj = parser.parse(date_time)
        localized_dt = EWSDateTime.from_datetime(dt_obj).astimezone(tz)
        return localized_dt
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def create_calendar_event(client, params, **kwargs):
    try:
        calendar_item = CalendarItem(
            folder=client.calendar,
            start=_datetime_conversion(params.get('start_date')),
            end=_datetime_conversion(params.get('end_date')),
            subject=params.get('subject'),
            body=HTMLBody(params.get('body')),
            location=params.get('location'),
            categories=str_to_list(params.get('categories')),
            is_all_day=params.get('is_all_day') if params.get('is_all_day') else False,
            reminder_minutes_before_start=minutes_dict.get(params.get('reminder_min')) if params.get('reminder_min') else 0,
            required_attendees=str_to_list(params.get('required_attendees')),
            optional_attendees=str_to_list(params.get('optional_attendees')),
            legacy_free_busy_status=params.get('legacy_free_busy_status'),
            sensitivity='Private' if params.get('private') else 'Normal'
        )
        res = calendar_item.save(send_meeting_invitations=SEND_ONLY_TO_ALL)
        logger.debug('Calender event created with {}'.format(res))
        return {"message": "Calender event created successfully"}
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_calendar_events(client, params, **kwargs):
    try:
        subject = params.get('subject')
        from_time = params.get('from_time')
        to_time = params.get('to_time')
        if not subject and not from_time and not to_time:
            result_set = client.calendar.all()
        else:
            temp = {}
            if subject:
                temp.update({'subject__contains': subject})
            if from_time:
                from_dt = _datetime_conversion(from_time)
                temp.update({'start__gt': from_dt})
            if to_time:
                to_dt = _datetime_conversion(to_time)
                temp.update({'end__lt': to_dt})
            result_set = client.calendar.filter(**temp)
        calender_lst = []
        for item in result_set:
            attach = []
            op_atend = []
            re_atend = []
            for i in item.required_attendees:
                re_atend.append(i.mailbox.email_address)
            if item.optional_attendees:
                for i in item.optional_attendees:
                    op_atend.append(i.mailbox.email_address)
            if item.attachments:
                for i in item.attachments:
                    attach.append({'Name': i.name, 'content_type': i.content_type, 'size': i.size})
            logger.info(item)
            lst = {'Start': item.start, 'End': item.end, 'Subject': item.subject, 'Body': item.body,
                   'Location': item.location, 'Organizer': item.organizer.email_address,
                   'Attachments': attach, 'Categories': item.categories,
                   'Importance': item.importance, 'Reminder is set': item.reminder_is_set,
                   'Reminder minutes before start': item.reminder_minutes_before_start,
                   'Is all day': item.is_all_day, 'Legacy status': item.legacy_free_busy_status,
                   'Required attendees': re_atend, 'sensitivity': item.sensitivity,
                   'Optional attendees': op_atend}
            calender_lst.append(lst)
        logger.info(calender_lst)
        return calender_lst
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))

