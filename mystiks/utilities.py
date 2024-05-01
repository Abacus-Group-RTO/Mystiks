#!/usr/bin/env python3
from re import search as search_regex


def unit_size_to_bytes(unit_size):
    table = {
        'TB': 1024 ** 4,
        'GB': 1024 ** 3,
        'MB': 1024 ** 2,
        'KB': 1024,
        'B': 1
    }

    match = search_regex(r'^([\s\d\.]+)(.*)$', unit_size)

    if not match:
        raise ValueError('The supplied unit size is invalid!')

    unit = match.group(2).strip().upper()

    if unit and unit not in table:
        raise ValueError('The supplied unit is not supported!')

    return int(match.group(1)) * table[unit or 'B']
