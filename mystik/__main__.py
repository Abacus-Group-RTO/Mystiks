#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path
from sys import exit
from time import time
from datetime import datetime as DateTime
from json import dumps as to_json
# from plotly import express as px, graph_objects as go
from re import split
from jinja2 import Template

from . import DEFAULT_SECRETS
from .mystik_core import recursive_regex_search


def items_to_json(items):
    output = {}

    for item in items:
        output[item.uuid] = {
            'fileName': item.file_name,
            'context': item.context,
            'contextStart': item.context_start,
            'contextEnd': item.context_end,
            'capture': item.capture,
            'pattern': item.pattern,
            'patternName': item.pattern_name,
            'captureStart': item.capture_start,
            'captureEnd': item.capture_end,
            'indicators': [('Matched pattern', 1)]
        }

    return output


def items_to_javascript(items):
    items = items_to_json(items)
    manifest = to_json({
        'items': items,
        'descriptions': {
            'Generic Access': [
                'Permissions in the Android Manifest file define the types of operations and data the application can access on the user\'s device. There are different categories of permissions depending on the potential risk to user privacy, divided mainly into Normal, Dangerous, Signature, and Special permissions.',
                'Normal permissions cover areas where your app needs to access data or resources outside the app\'s sandbox but pose minimal risk to the user\'s privacy. For example, an app might need to access the internet or set the time zone.',
                'Dangerous permissions, on the other hand, could potentially involve the user\'s private data or affect the operation of other apps or the system. This includes permissions like reading or writing to the user\'s contacts, accessing precise location, reading SMS messages, etc. For such permissions, the app must explicitly request the user\'s approval at runtime.',
            ]
        }
    }) #, indent=' ' * 4)
    return 'window.manifest = ' + manifest


def main():
    parser = ArgumentParser(description='Searches the given path for exposed secrets and outputs an HTML report.')
    parser.add_argument('path', help='The path to search for secrets in.')
    parser.add_argument('-n', '--name', help='The name of the report.')
    parser.add_argument('-o', '--output', help='The path to save the HTML report into.')
    # parser.add_argument('-l', '--limit', default='32MB', help='The maximum size to consider searchable files.')
    parser.add_argument('-t', '--threads', type=int, help='The amount of threads to use for searching.')
    # parser.add_argument('-v', '--verbosity', default=1, choices=['0', '1', '2', '3'], help='The level of verbosity to have.')
    arguments = parser.parse_args()

    # We start out by making sure that the target path exists.
    target_path = Path(arguments.path).resolve()

    if not target_path.exists():
        print('[-] The target path does not exist:', target_path)
        exit()

    started_at = time()
    items = recursive_regex_search(str(target_path), [('Generic Access', 'ACCESS[_A-Z]+')])

    with open('items.js', 'w') as file:
        file.write(items_to_javascript(items))

    print(f'{time() - started_at:.2f} seconds')


if __name__ == '__main__':
    main()
