#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps as to_json
from pathlib import Path
from shutil import Error as CopyError, copytree, rmtree
from sys import exit
from time import time

from .utilities import unit_size_to_bytes
from .searcher import build_manifest


def main():
    parser = ArgumentParser(description='Searches the given path for findings and outputs a report')
    parser.add_argument('path', help='The path to search for findings in')
    parser.add_argument('-n', '--name', help='The name of the report (Default: The target path\'s folder name)')
    parser.add_argument('-o', '--output', help='The path to save the report into (Default: Mystiks-<Report UUID>)')
    parser.add_argument('-l', '--limit', default='500MB', help='The maximum size a searchable file can be (Default: 500MB)')
    parser.add_argument('-t', '--threads', type=int, help='The amount of threads to use for searching (Default: Count of CPU cores)')
    parser.add_argument('-c', '--context', type=int, default=128, help='The amount of context to capture (Default: 128 bytes)')
    parser.add_argument('-f', '--formats', default='HTML,JSON', help='A comma-seperated list of formats to output (Default: HTML,JSON)')
    parser.add_argument('-u', '--utf16', action='store_true', help='Whether to search for UTF-16 strings (Default: Ignore UTF-16)')
    arguments = parser.parse_args()

    # We start out by making sure that the target path exists.
    target_path = Path(arguments.path).resolve()

    if not target_path.exists():
        print('[-] The target path does not exist:', target_path)
        exit()

    # We make sure that the formats are actually valid.
    output_formats = [output_format.upper() for output_format in arguments.formats.split(',')]

    if not output_formats:
        print('[-] You must specify at least one format: HTML,JSON')
        exit()

    for output_format in output_formats:
        if output_format not in ('HTML', 'JSON'):
            print('[-] You specified an invalid output format:', output_format)
            exit()

    max_file_size = unit_size_to_bytes(arguments.limit)
    file_name_map = None
    delete_after = False

    if target_path.is_file() and target_path.suffix.lower() == '.xml':
        try:
            from bs4 import BeautifulSoup
            from .burp import is_burp_xml, extract_requests

            file_size = target_path.stat().st_size

            if file_size < max_file_size:
                with open(target_path, 'r') as file:
                    soup = BeautifulSoup(file.read(), features='xml')

                if is_burp_xml(soup):
                    target_path, file_name_map = extract_requests(soup)
                    delete_after = True
            else:
                print('[-] The supplied file is too big:', file_size, '>', max_file_size)
                exit()
        except ImportError:
            print('[-] To extract requests from Burp XML, please install BeautifulSoup4 (and LXML): pip install beautifulsoup4 lxml')

    # This is where the majority of work happens.
    print('[i] Searching for findings, this may take a while:', target_path)

    manifest = build_manifest(
        path=target_path,
        desired_context=arguments.context,
        max_file_size=max_file_size,
        max_threads=arguments.threads,
        manifest_name=arguments.name,
        include_utf16=arguments.utf16,
        file_name_map=file_name_map
    )

    output_path = Path(arguments.output or 'Mystiks-{}'.format(round(time())))
    output_path.mkdir(exist_ok=True)

    if 'HTML' in output_formats:
        # Sometimes this can fail, even though it actually worked. To account
        # for this, we just ignore all errors.
        try:
            copytree(Path(__file__).parent / 'report', output_path, dirs_exist_ok=True)
        except CopyError:
            pass

        with open(output_path / 'scripts/data.js', 'w') as file:
            file.write('window.manifest=' + to_json(manifest, separators=(',', ':')))

        print('[+] An HTML copy of the report has been saved to:', output_path.resolve())
    if 'JSON' in output_formats:
        with open(output_path / 'report.json', 'w') as file:
            file.write(to_json(manifest, indent=' ' * 4))

        print('[+] A JSON copy of the report has been saved to:', output_path.resolve())

    if delete_after:
        rmtree(target_path)

    print('[+] All operations have finished!')
    print('[i] Findings discovered:', len(manifest['findings']))
    print('[i] Files scanned:', manifest['metadata']['totalFilesScanned'])
    print('[i] Directories scanned:', manifest['metadata']['totalDirectoriesScanned'])
    print('[i] Scanning took:', manifest['metadata']['completedAt'] - manifest['metadata']['startedAt'], 'second(s)')
