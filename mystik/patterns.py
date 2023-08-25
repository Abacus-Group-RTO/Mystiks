#!/usr/bin/env python3
from re import finditer, match as match_regex


def rebuild_pattern(pattern, replacements):
    '''
        This function takes the original pattern, a list of its replacements,
        and calculates a new pattern given the provided replacements.
    '''
    utf16_pattern = ''
    start_index = 0

    for indexes, replacement in replacements:
        if not replacement:
            continue

        utf16_pattern += pattern[start_index:indexes[0]]
        utf16_pattern += replacement
        start_index = indexes[1]

    utf16_pattern += pattern[start_index:]

    return utf16_pattern


def get_options_with_length_replacements_utf16(pattern):
    '''
        This function gets replacements for all RegEx options which specify
        their length.
    '''
    replacements = []

    for match in finditer(r'\[(.+?)\](\{(\d+)(?:, ?(\d+)?)?\})?', pattern):
        if not match.group(2):
            continue

        utf16_pattern = pattern[match.start(0):match.end(1)] + '\\x00'
        utf16_pattern += pattern[match.end(1):match.start(3)]
        utf16_pattern += str(int(match.group(3)) * 2)

        if match.group(4):
            utf16_pattern += pattern[match.end(3):match.start(4)]
            utf16_pattern += str(int(match.group(4)) * 2)
            utf16_pattern += pattern[match.start(4):match.end(0)]
        else:
            utf16_pattern += pattern[match.end(3):match.end(0)]

        replacements.append(((match.start(0), match.end(0)), utf16_pattern))

    return replacements


def get_options_with_range_replacements_utf16(pattern):
    '''
        This function gets replacements for all RegEx options which do not
        specify their length, but instead use `+` or `*` operators.
    '''
    replacements = []

    for match in finditer(r'\[(.+?)\]([*+])?', pattern):
        if not match.group(2):
            continue

        utf16_pattern = pattern[match.start(0):match.end(1)] + '\\x00'
        utf16_pattern += pattern[match.end(1):match.end(0)]

        replacements.append(((match.start(0), match.end(0)), utf16_pattern))

    return replacements


def get_options_replacements_utf16(pattern):
    '''
        This function gets replacements for all RegEx options.
    '''
    replacements = []

    for match in finditer(r'\[(.+?)\]([*+{])?', pattern):
        if match.group(2):
            continue

        utf16_pattern = match.group(0) + '\\x00'

        replacements.append(((match.start(0), match.end(0)), utf16_pattern))

    return replacements


def get_capture_with_length_replacements_utf16(pattern):
    '''
        This function is not used to get true replacements, but is instead
        used to compute ranges which should not be matched against by the
        general UTF-16 function.
    '''
    replacements = []

    for match in finditer(r'\(.+?\)(\{.+?\})?', pattern):
        if not match.group(1):
            continue

        replacements.append(((match.start(0), match.end(0)), None))

    return replacements


def get_flag_replacements_utf16(pattern):
    '''
        This function is not used to get true replacements, but is instead
        used to compute ranges which should not be matched against by the
        general UTF-16 function.
    '''
    replacements = []

    for match in finditer(r'\(\?[a-zA-Z]+?\)', pattern):
        replacements.append(((match.start(0), match.end(0)), None))

    return replacements


def get_letter_replacements_utf16(pattern, existing_replacements):
    '''
        This function is used to get replacements for each letter, converting
        them into UTF-16 compatible strings.
    '''
    replacements = []

    for match in finditer(r'[a-zA-Z0-9]|(?:\\\.)', pattern):
        overlaps_replacement = False

        for indexes, _ in existing_replacements:
            if match.start(0) >= indexes[0] and match.end(0) <= indexes[1]:
                overlaps_replacement = True
                break

        if overlaps_replacement:
            continue

        utf16_pattern = match.group(0) + '\\x00'

        replacements.append(((match.start(0), match.end(0)), utf16_pattern))

    final_replacement = replacements.pop() if replacements else None

    if final_replacement:
        replacements.append((final_replacement[0], final_replacement[1] + '?'))

    return replacements


def pattern_to_utf16(pattern):
    '''
        This function is used to convert a normal RegEx pattern into one that
        supports UTF-16.
    '''
    replacements = get_options_with_length_replacements_utf16(pattern)
    replacements += get_options_with_range_replacements_utf16(pattern)
    replacements += get_options_replacements_utf16(pattern)
    replacements += get_flag_replacements_utf16(pattern)
    replacements += get_capture_with_length_replacements_utf16(pattern)

    replacements += get_letter_replacements_utf16(pattern, replacements)
    replacements = sorted(replacements, key=lambda row: (row[0][0], row[0][1]))

    utf16_pattern = rebuild_pattern(pattern, replacements)

    return utf16_pattern


def create_patterns(findings, include_utf16=False, use_filters=True):
    '''
        Given a list of findings, this function creates a list of pattern tags
        and patterns. Dynamic creation of UTF-16 patterns is also supported,
        although this is not guaranteed to work in all situations.
    '''
    patterns = []

    # We do several things here, but most notable is the addition of the
    # pattern's intended encoding and support for dynamic UTF-16 patterns.
    for finding in findings:
        for index, pattern in enumerate(finding.patterns):
            filter_function = getattr(finding, 'should_filter_match', None)

            patterns.append((
                f'{index}:UTF-8:{finding.name}',
                pattern,
                filter_function if use_filters else None
            ))

            if include_utf16:
                patterns.append((
                    f'{index}:UTF-16:{finding.name}',
                    pattern_to_utf16(pattern),
                    filter_function if use_filters else None
                ))

    return patterns


def clean_match_utf16(match, finding):
    '''
        This functions cleans the supplied match data and accounts for the junk
        commonly found in UTF-16.
    '''
    zero_capture = match.capture[::2]
    zero_matched = False

    for pattern in finding.patterns:
        if match_regex(pattern.encode(), zero_capture):
            zero_matched = True
            break

    one_capture = match.capture[1::2]
    one_matched = False

    for pattern in finding.patterns:
        if match_regex(pattern.encode(), one_capture):
            one_matched = True
            break

    capture_start_offset = match.capture_start - match.context_start
    capture_end_offset = match.capture_end - match.context_start
    is_context_aligned = (capture_start_offset % 2) == 0
    pattern_index = int(match.pattern_tag.split(':', 2)[0])

    if zero_matched and not one_matched:
        return {
            'capture': zero_capture,
            'context': match.context[::2] if is_context_aligned else match.context[1::2],
            'capture_start': capture_start_offset // 2 if is_context_aligned else (capture_start_offset // 2) + 1,
            'capture_end': capture_end_offset // 2 if is_context_aligned else (capture_end_offset // 2) + 1,
            'groups': match_regex(finding.patterns[pattern_index].encode(), zero_capture).groups()
        }
    elif one_matched and not zero_matched:
        return {
            'capture': one_capture,
            'context': match.context[1::2] if is_context_aligned else match.context[::2],
            'capture_start': capture_start_offset // 2 if is_context_aligned else (capture_start_offset // 2) + 1,
            'capture_end': capture_end_offset // 2 if is_context_aligned else (capture_end_offset // 2) + 1,
            'groups': match_regex(finding.patterns[pattern_index].encode(), one_capture).groups()
        }

    # If we can't get the pattern to match, we assume it's a false-positive.
    return None
