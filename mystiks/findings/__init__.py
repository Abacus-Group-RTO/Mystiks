#!/usr/bin/env python3
from math import log2
from pathlib import Path
from importlib import import_module
from regex import finditer, match as match_regex


class Finding:
    ideal_rating = 5

    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups):
        return [('Capture matches pattern', 1)]


class SecretFinding(Finding):
    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups):
        '''
            It's important to keep in mind that this function produces a
            maximum rating of +1 or a minimum rating of -0.5.
        '''
        indicators = super().get_indicators(context, capture, capture_start, capture_end, groups)
        SEGMENTATION_LETTERS = b',:|\n\t '

        # We start by collecting the characters surrounding the capture.
        start_character = None

        if capture_start > 0:
            start_character = context[capture_start - 1]

        end_character = None

        if capture_end < len(context) - 1:
            end_character = context[capture_end]

        # We check whether the capture is the entirety of the file.
        if start_character == None and end_character == None:
            indicators.append(('Capture is the entire file', 1))
        # We check whether the capture is quoted or segmented.
        elif start_character != None and start_character == end_character:
            if start_character in b'\'"`':
                indicators.append(('Capture is quoted', 1))
            else:
                indicators.append(('Capture is segmented', 0.5))
        # We check whether the capture is defined as a value. TODO: Make this a regex.
        elif (start_character == ord('=') and (not end_character or end_character in b';\n\\ ,')):
            indicators.append(('Capture appears defined', 0.25))
        # We check whether the capture is at the start of a potentially-segmented file.
        elif (start_character == None and end_character and end_character in SEGMENTATION_LETTERS) \
                or (end_character == None and start_character and start_character in SEGMENTATION_LETTERS):
            indicators.append(('Capture appears segmented', 0.25))
        else:
            indicators.append(('Capture is not segmented', -0.5))

        return indicators


def get_shannon_entropy(string):
    frequency = {}

    for character in string:
        frequency[character] = frequency.get(character, 0) + 1

    entropy = 0

    for count in frequency.values():
        probability = count / len(string)
        entropy += probability * log2(probability)

    return -entropy


def get_relative_shannon_entropy(string):
    entropy = get_shannon_entropy(string)
    max_entropy = log2(len(set(string)))
    return entropy / max_entropy


def get_sequence_rating(string, max_distance=1):
    last_character = string[0]
    sequences = 0

    for character in string[1:]:
        if abs(ord(character) - ord(last_character)) <= max_distance:
            sequences += 1

        last_character = character

    return sequences / (len(string) - 1)


def build_pronouncable_regex():
    vowels = ('a', 'e', 'i', 'o', 'u', 'y')

    consonants = (
        'b', 'bl', 'br', 'c', 'ch', 'cr', 'chr', 'cl', 'ck', 'd', 'dr', 'f',
        'fl', 'g', 'gl', 'gr', 'h', 'j', 'k', 'l', 'll', 'm', 'n', 'p', 'ph',
        'pl', 'pr', 'q', 'r', 's', 'sc', 'sch', 'sh', 'sl', 'sp', 'st', 't',
        'th', 'thr', 'tr', 'v', 'w', 'wr', 'x', 'y', 'z'
    )

    vowel_regex = '({})'.format('|'.join(vowels))
    consonant_regex = '({})'.format('|'.join(consonants))

    return r'(?i)^{1}?{1}?({0}+{1}{1}?)*{0}*$'.format(vowel_regex, consonant_regex)


def check_pronounceable_by_regex(string):
    return match_regex(build_pronouncable_regex(), string) != None


def check_pronounceable_by_repetition(string, max_vowel_repetitions=3, max_consonant_repetitions=4):
    repeated_vowels = 0
    repeated_consonants = 0

    for character in string.lower():
        if character not in 'abcdefghijklmnopqrstuvwxyz':
            return False

        if character in 'aeiou':
            repeated_vowels += 1
            repeated_consonants = 0
        else:
            repeated_consonants += 1
            repeated_vowels = 0

        if repeated_vowels > max_vowel_repetitions or repeated_consonants > max_consonant_repetitions:
            return False

    return True


def get_pronounceable_rating(string):
    pronouncable = 0

    for match in finditer(r'(?:([A-Z]?[a-z]{2,}))|(?:([a-z]?[A-Z]{2,}))', string):
        factor = 0

        if check_pronounceable_by_repetition(match.group(0)):
            factor += 0.25

        if check_pronounceable_by_regex(match.group(0)):
            factor += 0.75

        pronouncable += len(match.group(0)) * factor

    return pronouncable / len(string)


def get_character_counts(string):
    letter_count = 0
    number_count = 0
    symbol_count = 0

    for match in finditer(r'(?i)([a-z]+)|([0-9]+)|([^a-z0-9]+)', string):
        letters, numbers, symbols = match.group(1, 2, 3)

        if letters:
            letter_count += len(match.group(0))
        elif numbers:
            number_count += len(match.group(0))
        elif symbols:
            symbol_count += len(match.group(0))

    return letter_count, number_count, symbol_count


# We automatically build out a list of available findings.
FINDINGS = []

for file in Path(__file__).parent.glob('*.py'):
    # We skip any files that my be internally used by Python.
    if file.name.startswith('__'):
        continue

    # We extend out the findings list with our types.
    module_findings = getattr(import_module(f'mystiks.findings.{file.stem}'), 'FINDINGS', None)

    if module_findings:
        FINDINGS.extend(module_findings)
