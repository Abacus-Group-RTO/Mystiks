#!/usr/bin/env python3
from base64 import standard_b64decode, standard_b64encode
from time import time
from math import ceil

from .mystik_core import recursive_regex_search


def build_manifest(path, target_findings, manifest_name=None):
    started_at = ceil(time())
    unique_files = []
    patterns = []
    mappings = {}

    for finding in target_findings:
        for pattern in finding.patterns:
            patterns.append((finding.name, pattern))

        mappings[finding.name] = finding

    max_file_size = 1024 * 1024 * 1024

    result = recursive_regex_search(str(path), [(n, p.encode()) for n, p in patterns], 128)

    print(result.scan_started_at)
    print(result.scan_completed_at)
    print(result.total_files_scanned)
    print(result.total_directories_scanned)

    matches = result.matches

    manifest = {
        'metadata': {},
        'descriptions': {},
        'sorting': [],
        'findings': {},
    }

    for match in matches:
        finding = mappings[match.pattern_tag]

        indicators = finding.get_indicators(
            context=match.context,
            context_start=match.context_start,
            context_end=match.context_end,
            capture=match.capture,
            capture_start=match.capture_start - match.context_start,
            capture_end=match.capture_end - match.context_start,
            groups=match.groups
        )

        rating = sum([delta for _, delta in indicators])

        if rating < 0:
            continue

        if match.file_name not in unique_files:
            unique_files.append(match.file_name)

        manifest['findings'][match.uuid] = {
            'fileName': match.file_name,
            'groups': [standard_b64encode(group).decode() for group in match.groups],
            'context': standard_b64encode(match.context).decode(),
            'contextStart': match.context_start,
            'contextEnd': match.context_end,
            'capture': standard_b64encode(match.capture).decode(),
            'pattern': match.pattern,
            'patternName': match.pattern_tag,
            'captureStart': match.capture_start,
            'captureEnd': match.capture_end,
            'indicators': indicators,
            'rating': rating,
            'idealRating': finding.ideal_rating
        }

        if not finding.name in manifest['descriptions']:
            manifest['descriptions'][finding.name] = finding.description

    # We compute ratings for each of the findings.
    ratings = {}

    for uuid, finding in manifest['findings'].items():
        ratings[uuid] = finding['rating'] / finding['idealRating']

    # We include a pre-computed sorting of the values, just to save time later.
    manifest['sorting'] = list(sorted(ratings, key=ratings.get, reverse=True))

    # We staple on some metadata to the manifest.
    manifest['metadata']['name'] = manifest_name or path.name
    manifest['metadata']['startedAt'] = started_at
    manifest['metadata']['completedAt'] = ceil(time())
    manifest['metadata']['uniqueFiles'] = len(unique_files)

    return manifest
