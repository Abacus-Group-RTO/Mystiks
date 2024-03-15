#!/usr/bin/env python3
from base64 import standard_b64decode
from secrets import token_hex
from pathlib import Path
from tempfile import mkdtemp


def is_burp_xml(soup):
    items = soup.find('items')

    if not items:
        return False

    return items.has_attr('burpVersion')


def extract_requests(soup):
    temporary_folder = Path(mkdtemp())
    file_name_map = {}

    for item in soup.find_all('item'):
        alias = token_hex(16)
        file_name_map[alias] = item.find('url').string

        with open(temporary_folder / (alias + '-request'), 'wb') as file:
            file.write(standard_b64decode(item.find('request').string))

        with open(temporary_folder / (alias + '-response'), 'wb') as file:
            file.write(standard_b64decode(item.find('response').string))

    return temporary_folder, file_name_map
