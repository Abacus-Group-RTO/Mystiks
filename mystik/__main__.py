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

from .findings.jwt import JSONWebToken
from .findings.amazon import AmazonToken
from .searcher import build_manifest


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
    manifest = build_manifest(target_path, [AmazonToken, JSONWebToken])

    with open('data.js', 'w') as file:
        file.write('window.manifest = ' + to_json(manifest, indent=' ' * 4))

    print(f'{time() - started_at:.2f} seconds')


if __name__ == '__main__':
    main()
