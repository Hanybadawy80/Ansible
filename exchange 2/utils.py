""" Copyright start
  Copyright (C) 2008 - 2024 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


"""
Steps related to fetching and parsing email
"""
from exchangelib import Q, EWSTimeZone, EWSDateTime
from dateutil import parser
import re
from connectors.core.connector import get_logger
from datetime import datetime

logger = get_logger('exchange')

def str_to_list(input_str):
    if isinstance(input_str, str) and len(input_str) > 0:
        return [x.strip() for x in input_str.split(',')]
    elif isinstance(input_str, list):
        return input_str
    else:
        return []


def build_advanced_query(query_string, client):
    pattern = "datetime_[^=]*='\d{4}-\d{2}-\d{2}'"
    pattern2 = "datetime_[^=]*='\d{4}-\d{2}-\d{2}.\d{2}:\d{2}:\d{2}Z?'"
    dates = re.findall(pattern, query_string)
    dates.extend(re.findall(pattern2, query_string))
    tz = client.default_timezone
    for date in dates:
        date_ = date.split("=")
        field = date_[0]
        old_value = date_[1]
        dt_obj = parser.parse(date_[1])
        converted_date = f'{field}=datetime(dt_obj.year, dt_obj.month, dt_obj.day, dt_obj.hour, dt_obj.minute, dt_obj.second, tzinfo=tz)'
        query_string = query_string.replace(f"{field}={old_value}", converted_date)
    return eval(query_string)

