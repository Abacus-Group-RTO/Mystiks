#!/usr/bin/env python3
from argparse import ArgumentParser
from json import dumps as to_json
from pathlib import Path
from sys import exit
from shutil import Error as CopyError, copytree

from .mystik_core import recursive_regex_search # noqa: F401,E261
from .utilities import unit_size_to_bytes
from .searcher import build_manifest


def main():
    parser = ArgumentParser(description='Searches the given path for findings and outputs a report')
    parser.add_argument('path', help='The path to search for findings in')
    parser.add_argument('-n', '--name', help='The name of the report (Default: The target path\'s folder name)')
    parser.add_argument('-o', '--output', help='The path to save the report into (Default: Mystik-<Report UUID>)')
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

    # This is where the majority of work happens.
    print('[i] Searching for findings, this may take a while.')

    manifest = build_manifest(
        path=target_path,
        desired_context=arguments.context,
        max_file_size=unit_size_to_bytes(arguments.limit),
        max_threads=arguments.threads,
        manifest_name=arguments.name,
        include_utf16=arguments.utf16
    )

    output_path = Path(arguments.output or 'Mystik-{}'.format(manifest['metadata']['uuid']))
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

    print('[+] All operations have finished!')
    print('[i] Findings discovered:', len(manifest['findings']))
    print('[i] Files scanned:', manifest['metadata']['totalFilesScanned'])
    print('[i] Directories scanned:', manifest['metadata']['totalDirectoriesScanned'])
    print('[i] Scanning took:', manifest['metadata']['completedAt'] - manifest['metadata']['startedAt'], 'second(s)')
