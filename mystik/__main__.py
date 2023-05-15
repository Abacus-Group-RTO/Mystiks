#!/usr/bin/env python3
from argparse import ArgumentParser
from pathlib import Path
from sys import exit
from time import time
from datetime import datetime as DateTime
from json import dumps as to_json
from plotly import express as px, graph_objects as go
from re import split
from jinja2 import Template

from . import DEFAULT_SECRETS
from .searchers import build_manifest, secret_searcher
from .workers import WorkerPool


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

    timestamp = DateTime.utcnow().strftime('%m%d%y-%H%M')
    default_name = f'Mystik-Report-{timestamp}'

    # Next, we make sure the HTML report's parent exists.
    if arguments.output:
        output_path = Path(arguments.output).resolve()
    else:
        output_path = Path(f'{default_name}.html').resolve()

    if not output_path.parent.exists():
        print('[-] The output path\'s parent does not exist:', output_path)
        exit()

    # Our pre-setup is done, time to begin the search!
    started_at = time()

    # We create a manifest for our search.
    print('[i] Building a manifest of the target path...')
    manifest = build_manifest(target_path)

    print('[i] Starting a worker pool to search for secrets...')
    pool = WorkerPool()
    pool.add_tasks(manifest)
    pool.work_tasks(secret_searcher, kwargs={
        'secrets': DEFAULT_SECRETS
    }, worker_count=arguments.threads)

    time_taken = round(time() - started_at, 2)

    # We attempt to de-duplicate the results before passing them on.
    print('[i] Deduplicating results...')

    file_hits = {}
    secret_types = {}
    best_results = {}

    for result in pool.results:
        file_path = '/'.join(result['filePath'])
        file_hits[file_path] = file_hits.get(file_path, 0) + 1
        secret_types[result['secretType']] = secret_types.get(result['secretType'], 0) + 1
        key = ':'.join([result['secretType'], '/'.join(result['filePath']), str(result['matchStart'])])
        existing_result = best_results.get(key)

        if not existing_result or existing_result['totalWeight'] < result['totalWeight']:
            best_results[key] = result

    del pool.results
    final_results = list(best_results.values())
    del best_results

    # print('[i] Filtering out results with a low Quality-of-Detection...')
    # reasonable_results = []

    # for result in best_results.values():
    #     if result['totalWeight'] >= 1:
    #         reasonable_results.append(result)

    # del best_results

    print('[i] Writing the report to a file...')
    folder = Path(__file__).parent

    with open(folder / 'template.jinja2', 'r') as file:
        report = file.read()

    result_object = {
        'targetPath': split(r'[\\/]', str(target_path)),
        'reportName': arguments.name or default_name,
        'secretCount': len(final_results),
        'fileCoverage': len(manifest),
        'searchDuration': time_taken,
        'timestamp': DateTime.utcnow().strftime('%B %d, %Y')
    }

    # replacement = 'window.reportMetadata = ' + to_json(result_object, indent=' ' * 4, sort_keys=True)

    # report = report.replace('window.reportMetadata = {}', replacement)

    # replacement = 'window.reportResults = ' + to_json(final_results, indent=' ' * 4, sort_keys=True)

    # report = report.replace('window.reportResults = []', replacement)

    template = Template(report)

    charts = {}

    fig = px.pie(names=secret_types.keys(), values=secret_types.values(), color_discrete_sequence=px.colors.sequential.Agsunset)
    fig.update_layout(autosize=True)
    charts['Distribution of Secret Types'] = fig

    top_file_hits = sorted(file_hits, key=file_hits.get, reverse=True)[:10]

    fig = px.pie(names=top_file_hits, values=[file_hits[key] for key in top_file_hits], color_discrete_sequence=px.colors.sequential.Agsunset)
    fig.update_layout(autosize=True)
    charts['Most Occurrences by File'] = fig

    report = template.render(
        report_metadata=to_json(result_object, indent=' ' * 4, sort_keys=True),
        report_results=to_json(final_results, indent=' ' * 4, sort_keys=True),
        charts=charts
    )

    with open(output_path, 'w') as file:
        file.write(report)

    print('[+] Search was completed over', len(manifest), 'files with', len(final_results), 'matches found.', f'(Searching took {time_taken:.2f} seconds)')
    print('[i] The report was saved to:', output_path)


if __name__ == '__main__':
    main()
