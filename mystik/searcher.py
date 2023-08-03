#!/usr/bin/env python3
from base64 import standard_b64decode
from time import time
from math import ceil

from .mystik_core import recursive_regex_search


def build_manifest(path, target_findings):
    started_at = ceil(time())
    unique_files = []
    patterns = []
    mappings = {}

    for finding in target_findings:
        for pattern in finding.patterns:
            patterns.append((finding.name, pattern))

        mappings[finding.name] = finding

    matches = recursive_regex_search(str(path), patterns)

    manifest = {
        'findings': {},
        'descriptions': {},
        'metadata': {}
    }

    for match in matches:
        finding = mappings[match.pattern_name]

        indicators = finding.get_indicators(
            context=standard_b64decode(match.context.encode()),
            context_start=match.context_start,
            context_end=match.context_end,
            capture=standard_b64decode(match.capture.encode()),
            capture_start=match.capture_start - match.context_start,
            capture_end=match.capture_end - match.context_start,
            groups=[standard_b64decode(group.encode()) for group in match.groups]
        )

        value = sum([delta for _, delta in indicators]) / len(indicators)

        if value < 0:
            continue

        if match.file_name not in unique_files:
            unique_files.append(match.file_name)

        manifest['findings'][match.uuid] = {
            'fileName': match.file_name,
            'groups': match.groups,
            'context': match.context,
            'contextStart': match.context_start,
            'contextEnd': match.context_end,
            'capture': match.capture,
            'pattern': match.pattern,
            'patternName': match.pattern_name,
            'captureStart': match.capture_start,
            'captureEnd': match.capture_end,
            'indicators': indicators
        }

        if not finding.name in manifest['descriptions']:
            manifest['descriptions'][finding.name] = finding.description

        manifest['metadata']['started_at'] = started_at
        manifest['metadata']['completed_at'] = ceil(time())
        manifest['metadata']['unique_files'] = len(unique_files)

    return manifest
