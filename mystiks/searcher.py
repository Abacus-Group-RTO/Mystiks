#!/usr/bin/env python3
from base64 import standard_b64encode
from pathlib import Path

from .findings import FINDINGS
from .mystiks_core import recursive_regex_search
from .patterns import create_patterns, clean_match_utf16


def build_manifest(path, target_findings=None, desired_context=None, max_file_size=None, max_threads=None, manifest_name=None, include_utf16=False, file_name_map=None):
    target_findings = target_findings or FINDINGS

    # We prepare the RegEx patterns for searching.
    patterns = create_patterns(target_findings, include_utf16)

    # We send out our recursive RegEx search!
    search_result = recursive_regex_search(
        path=str(path),
        patterns=patterns,
        excluded_file_patterns=[
            r'(?i)^.+\.svg$',
            r'(?i)^.+\.png$',
            r'(?i)^.+\.gif$',
            r'(?i)^.+\.jpeg$',
            r'(?i)^.+\.jpg$',
            r'(?i)^.+\.ttf$',
        ],
        desired_context=desired_context,
        max_file_size=max_file_size,
        max_threads=max_threads
    )

    # We start by preparing a map of finding names to findings.
    mappings = {}

    for finding in target_findings:
        mappings[finding.name] = finding

    # We start building the manifest.
    manifest = {
        'metadata': {},
        'descriptions': {},
        'sorting': [],
        'findings': {},
    }

    ratings = {}

    for match in search_result.matches:
        pattern_index, pattern_encoding, finding_name = match.pattern_tag.split(':', 2)
        finding = mappings[finding_name]
        cleaned_capture = None

        if pattern_encoding == 'UTF-16':
            cleaned_match = clean_match_utf16(match, finding)

            if not cleaned_match:
                continue

            indicators = finding.get_indicators(**cleaned_match)
            cleaned_capture = cleaned_match['capture']
        else:
            indicators = finding.get_indicators(
                context=match.context,
                capture=match.capture,
                capture_start=match.capture_start - match.context_start,
                capture_end=match.capture_end - match.context_start,
                groups=match.groups
            )

        # We calculate each finding's rating here. If the rating is too low,
        # we skip this finding and remove it.
        rating = sum([delta for _, delta in indicators])

        if rating < getattr(finding, 'min_rating', 0):
            continue

        if file_name_map:
            file_name = file_name_map.get(Path(match.file_name).stem.split('-')[0], match.file_name)

            if 'request' in match.file_name:
                file_name = f'Request -> {file_name}'
            elif 'response' in match.file_name:
                file_name = f'Response <- {file_name}'
        else:
            file_name = match.file_name

        # We can now create a manifest entry, yay!
        manifest['findings'][match.uuid] = {
            'fileName': file_name,
            'groups': [standard_b64encode(group).decode() for group in match.groups],
            'context': standard_b64encode(match.context).decode(),
            'contextStart': match.context_start,
            'contextEnd': match.context_end,
            'capture': standard_b64encode(cleaned_capture or match.capture).decode(),
            'captureStart': match.capture_start,
            'captureEnd': match.capture_end,
            'pattern': match.pattern,
            'name': finding_name,
            'indicators': indicators,
            'rating': rating,
            'idealRating': finding.ideal_rating
        }

        # We collect each finding's rating for later sorting.
        ratings[match.uuid] = rating / finding.ideal_rating

        # If the finding hasn't been added to the descriptions table, we add
        # that in now.
        if finding.name not in manifest['descriptions']:
            manifest['descriptions'][finding.name] = finding.description

    # We include a pre-computed sorting of the values, just to save time later.
    manifest['sorting'] = list(sorted(ratings, key=ratings.get, reverse=True))

    # We staple on some metadata to the manifest.
    manifest['metadata']['uuid'] = search_result.uuid
    manifest['metadata']['name'] = manifest_name or path.name
    manifest['metadata']['startedAt'] = search_result.scan_started_at
    manifest['metadata']['completedAt'] = search_result.scan_completed_at
    manifest['metadata']['totalFilesScanned'] = search_result.total_files_scanned
    manifest['metadata']['totalDirectoriesScanned'] = search_result.total_directories_scanned

    return manifest
