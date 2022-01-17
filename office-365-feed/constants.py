"""
  Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end
"""
ipv4Regex = r'\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b([^\/]|$)'
ipv4cidrRegex = r'\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\[\.\]|\.)){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\/([0-9]|[1-2][0-9]|3[0-2]))\b'  # noqa: E501
ipv6Regex = r'\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:(?:(:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b'  # noqa: E501
ipv6cidrRegex = r'\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/(12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9]))\b'  # noqa: E501

INDICATOR_TYPE_MAP = {'MISP Event': '/api/3/picklists/ec8b8c0a-825e-4c6d-8ad2-628100d6da76',
                      'Network Activity': '/api/3/picklists/ce20efe5-622e-4c05-be81-5210d12988ef',
                      'IP Address': '/api/3/picklists/b788efc2-dadb-4448-9018-043b37266de4',
                      'IPv4 Address': '/api/3/picklists/7a874c06-b65b-4850-9dd0-ff1c1db6491f',
                      'IPv6 Address': '/api/3/picklists/00180d62-b914-4522-bd68-4914eb484841',
                      'FileHash': '/api/3/picklists/8c88bc82-c803-4cba-9997-4d734123493b',
                      'FileHash-MD5': '/api/3/picklists/393cc8c8-da97-414a-9058-ee177c946bed',
                      'FileHash-SHA256': '/api/3/picklists/b1bbe31b-6121-45d5-9acb-94f67edbd7ba',
                      'FileHash-SHA1': '/api/3/picklists/0aa43df6-3331-4994-a442-8543f7e17365',
                      'Domain': '/api/3/picklists/18c5c903-eda5-494d-aa7e-f28b479681ac',
                      'URL': '/api/3/picklists/76b68a66-ffaa-4003-b60d-a43fcc64c003',
                      'Process': '/api/3/picklists/22ff2fc7-e1bb-4d68-b1c1-990618639731',
                      'Port': '/api/3/picklists/b8bc8bf3-5162-478e-9fe8-1ff54b0d9721',
                      'Actor': '/api/3/picklists/6b149497-4f2a-4843-8137-cbdcfd6f90f1',
                      'Software': '/api/3/picklists/a0094047-6423-4a7c-8e59-e8d0e425e4f3',
                      'Filename': '/api/3/picklists/a73a2378-92b2-4c6e-952c-ec340ea565a6'}

REPUTATION_MAP = {'Suspicious': '/api/3/picklists/50bfd06c-9aff-4f7d-b6d9-821339e31fe7',
                  'Malicious': '/api/3/picklists/7074e547-7785-4979-be32-c6d0c863e4bd',
                  'No Reputation Available': '/api/3/picklists/9a611980-1b5e-4ae9-8062-eb2c0c433cff',
                  'TBD': '/api/3/picklists/ae98ebc6-beef-4882-9980-1d88fc6d87cd',
                  'Good': '/api/3/picklists/b19b42aa-aee4-47df-9cda-894537dacb2a'}

TLP_MAP = {'Red': '/api/3/picklists/0472d368-bd15-4f52-a119-d403470cbe43',
           'Amber': '/api/3/picklists/7bff95b7-6438-4b01-b23a-0fe8cb5b33d3',
           'Green': '/api/3/picklists/47004ad3-721e-43e0-b729-2ad8ee6441c0',
           'White': ''}
