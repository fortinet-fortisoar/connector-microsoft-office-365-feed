"""
  Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end
"""
import requests
import uuid
import datetime
import time
import re
from .constants import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('office-365-feed')


def ip_to_indicator_type(ip):
    # Returns the indicator type of the input IP.
    if re.match(ipv4cidrRegex, ip):
        return "IPv4 Address"

    elif re.match(ipv4Regex, ip):
        return "IPv4 Address"

    elif re.match(ipv6cidrRegex, ip):
        return "IPv6 Address"

    elif re.match(ipv6Regex, ip):
        return "IPv6 Address"

    else:
        return None


def check_indicator_type(indicator):
    # Checks the indicator type.
    is_ip_indicator = ip_to_indicator_type(indicator)
    if is_ip_indicator:
        return is_ip_indicator
    elif '*' in indicator:
        return "URL"
    else:
        return "URL"


def convert_str_list(params):
    if not params:
        return []
    param_list = list(map(lambda x: x.strip(' '), params.split(','))) if isinstance(params, str) else params
    return param_list


def get_datetime(_epoch):
    pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
    return str(datetime.datetime.utcfromtimestamp(_epoch).strftime(pattern))


def max_age(params):
    if params.get("expiry") is not None and params.get("expiry") != '':
        return int(time.time()) + (params.get("expiry") * 86400)
    else:
        # Setting the default expiry time to 15 days from the indicator fetch time.
        return int(time.time()) + (15 * 86400)


def build_urls_dict(regions_list, services_list, unique_id, endpoint, latest_version_list=[]):
    try:
        urls_list = []
        service = ','.join(map(str, services_list))
        for region in regions_list:
            if service == 'All':
                url = 'https://endpoints.office.com/{0}/{1}?ClientRequestId={2}'.format(endpoint, region, unique_id)
            else:
                url = 'https://endpoints.office.com/{0}/{1}?ServiceAreas={2}' \
                      '&ClientRequestId={3}'.format(endpoint, region, service, unique_id)

            if latest_version_list:
                for dict_ in [x for x in latest_version_list if x["instance"] == region]:
                    urls_list.append({'lastUpdated': dict_.get("latest"),
                                      'region': region,
                                      'feedURL': url,
                                      })
            else:
                urls_list.append({
                    'region': region,
                    'feedURL': url
                })

        return urls_list
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def make_api_call(params):
    # Retrieves all entries from the feed.
    try:
        result = []
        for feed_obj in params.get('urls_list'):
            feed_url = feed_obj.get('feedURL', '')
            try:
                response = requests.get(
                    url=feed_url,
                    verify=params.get('verify_ssl')
                )
                response.raise_for_status()
                data = response.json()
                if "latest" in data:
                    result.append(data)
                else:
                    indicators = [i for i in data if 'ips' in i or 'urls' in i]  # filter empty entries
                    result.extend(indicators)
            except requests.exceptions.SSLError:
                logger.error('An SSL error occurred.')
                raise ConnectorError('An SSL error occurred.')
            except requests.exceptions.ConnectionError:
                logger.error('A connection error occurred.')
                raise ConnectorError('A connection error occurred.')
            except Exception as err:
                logger.error(err)
                raise ConnectorError(err)
        return result
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def get_latest_version(config):
    try:
        client_request_id = str(uuid.uuid4())
        regions_list = convert_str_list(config.get('regions'))
        params = {"urls_list": build_urls_dict(regions_list, services_list=["All"], unique_id=client_request_id,
                                               endpoint="version"),
                  "verify_ssl": config.get("verify_ssl")}

        resp = make_api_call(params)
        return resp
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def fetch_last_updated_time(config, last_pull_time):
    region = config.get('regions')
    latest_version_list = get_latest_version(config)
    for version in latest_version_list:
        if version["instance"] == region:
            latest_time = version["latest"]
            try:
                old_version_ts = datetime.datetime.strptime(str(last_pull_time), "%Y-%m-%dT%H:%M:%SZ").timestamp()
            except:
                old_version_ts = last_pull_time
            latest_version_ts = int(datetime.datetime.strptime(latest_time, "%Y%m%d%H").timestamp())
            if old_version_ts < latest_version_ts:
                return True, latest_version_list
    return False, None


def handle_dedup(iterable):
    # Remove duplicate entries from result
    try:
        seen = set()
        result = []

        for dic in iterable:
            key = (dic['value'])
            if key in seen:
                continue
            result.append(dic)
            seen.add(key)
        return result

    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def build_response(indicator_fields, indicator_type_lower, limit=-1):
    try:
        iterator = make_api_call(indicator_fields)
        result = indicator_fields["urls_list"][0]
        # filter indicator_type specific entries
        if not indicator_type_lower == 'both':
            iterator = [i for i in iterator if indicator_type_lower in i]
        indicators = []

        for item in iterator:
            if indicator_type_lower == 'both':
                values = item.get('ips', []) + item.get('urls', [])
            else:
                values = item.get(indicator_type_lower)
            if values:
                for value in values:
                    type_ = check_indicator_type(value)
                    raw_data = {
                        'value': value,
                        'type': type_,
                    }
                    for key, val in item.items():
                        if key not in ['ips', 'urls']:
                            raw_data.update({key: val})

                    raw_data['tlp'] = indicator_fields['tlp'] if indicator_fields['tlp'] else ""
                    raw_data['confidence'] = indicator_fields['confidence'] if indicator_fields['confidence'] else ""
                    raw_data['reputation'] = indicator_fields['reputation'] if indicator_fields['reputation'] else ""
                    raw_data['validUntil'] = indicator_fields['validUntil'] if indicator_fields['validUntil'] else ""
                    indicators.append(raw_data)

        unique_indicators = handle_dedup(indicators)
        result["indicators"] = unique_indicators[:limit] if limit > 0 else unique_indicators
        return result

    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def fetch_indicator(config, params):
    try:
        last_pull_time = params.get("last_pull_time")
        if last_pull_time != "" and last_pull_time != None and last_pull_time != 0:
            flag, latest_version_list = fetch_last_updated_time(config, last_pull_time)
        else:
            latest_version_list = get_latest_version(config)
            flag = True
        if flag:
            indicator_fields = dict()
            client_request_id = str(uuid.uuid4())
            regions_list = convert_str_list(config.get('regions'))
            services_list = convert_str_list(config.get('services'))
            indicator_fields['urls_list'] = build_urls_dict(regions_list, services_list, client_request_id, "endpoints",
                                                            latest_version_list)
            indicator_fields['verify_ssl'] = config.get('verify_ssl', False)
            indicator_fields['confidence'] = params.get("confidence") if params.get(
                "confidence") is not None and params.get(
                "confidence") != '' else 0
            indicator_fields['reputation'] = params.get("reputation") if params.get(
                'reputation') is not None and params.get("reputation") != '' else "TBD"
            indicator_fields['tlp'] = params.get("tlp") if params.get("tlp") is not None and params.get(
                "tlp") != '' else "White"
            indicator_fields['validUntil'] = max_age(params)
            indicator_type = str(params.get('indicator_type'))
            indicator_type_lower = indicator_type.lower()
            limit = int(params.get('limit'))
            indicators = build_response(indicator_fields, indicator_type_lower, limit)
            return indicators
        else:
            return {"result": "Indicators are upto date"}

    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def check_health(config):
    try:
        client_request_id = str(uuid.uuid4())
        regions_list = convert_str_list(config.get('regions'))
        services_list = convert_str_list(config.get('services'))
        params = {'urls_list': build_urls_dict(regions_list, services_list, client_request_id, endpoint="endpoints"),
                  'verify_ssl': config.get('verify_ssl')}

        resp = make_api_call(params)
        if resp:
            return True
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


operations = {
    "fetch_indicator": fetch_indicator
}
