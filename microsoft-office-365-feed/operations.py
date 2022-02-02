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
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('microsoft-office-365-feed')


def convert_str_list(params):
    if not params:
        return []
    param_list = list(map(lambda x: x.strip(' '), params.split(','))) if isinstance(params, str) else params
    return param_list


def build_urls_dict(region, services_list, unique_id, endpoint, latest_version_list=[]):
    try:
        urls_list = []
        service = ','.join(map(str, services_list))

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
        region = config.get('regions')
        params = {"urls_list": build_urls_dict(region, services_list=["All"], unique_id=client_request_id,
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


def build_response(indicator_fields, indicator_type_lower, limit=-1):
    iterator = make_api_call(indicator_fields)
    result = indicator_fields["urls_list"][0]
    # filter indicator_type specific records
    if not indicator_type_lower == 'both':
        iterator = [i for i in iterator if indicator_type_lower in i]
    indicators = []

    for item in iterator:
        if indicator_type_lower == 'both':
            records = {'IP': item.get('ips', []),
                       'URL': item.get('urls', [])}

        elif indicator_type_lower == 'ips':
            records = {'IP': item.get('ips', [])}
        else:
            records = {'URL': item.get('urls', [])}

        for type_, values in records.items():
            for value in values:
                raw_data = {
                    'value': value,
                    'type': type_,
                }
                for key, val in item.items():
                    if key not in ['ips', 'urls']:
                        raw_data.update({key: val})
                indicators.append(raw_data)

    unique_indicators = handle_deduplication(indicators)
    result["indicators"] = unique_indicators[:limit] if limit > 0 else unique_indicators
    return result


def handle_deduplication(iterable):
    seen = set()
    result = []

    for dic in iterable:
        key = (dic['value'])
        if key in seen:
            continue
        result.append(dic)
        seen.add(key)
    return result


def fetch_indicator(config, params):
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
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
            region = config.get('regions')
            services_list = convert_str_list(config.get('services'))
            indicator_fields['urls_list'] = build_urls_dict(region, services_list, client_request_id, "endpoints",
                                                            latest_version_list)
            indicator_fields['verify_ssl'] = config.get('verify_ssl', False)
            indicator_type = str(params.get('indicator_type')).lower()
            limit = int(params.get('limit'))
            indicators = build_response(indicator_fields, indicator_type, limit)
            return indicators
        else:
            return {"result": "Indicators are upto date"}

    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def check_health_ex(config):
    try:
        client_request_id = str(uuid.uuid4())
        region = config.get('regions')
        services_list = convert_str_list(config.get('services'))
        params = {'urls_list': build_urls_dict(region, services_list, client_request_id, endpoint="endpoints"),
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
