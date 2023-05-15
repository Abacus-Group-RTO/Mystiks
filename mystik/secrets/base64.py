#!/usr/bin/env python3
from re import compile as RegEx, findall as find_all, IGNORECASE
from base64 import b64decode
from binascii import Error as BinaryError

from . import Secret, SecretExpression, get_average_byte, get_shannon_entropy


class Base64(Secret):
    def __init__(self):
        super().__init__(
            name='Base64',
            expressions=[
                SecretExpression(r'[a-z0-9\+/]{8,}', flags=IGNORECASE, weight=0.25),
                SecretExpression(r'[a-z0-9\+/]{8,}={1,2}', flags=IGNORECASE, weight=0.75)
            ]
        )

        self.build_pronouncable_regex()

    def build_pronouncable_regex(self):
        vowels = [
            'a', 'e', 'i', 'o', 'u', 'y'
        ]

        consonants = [
            'b', 'bl', 'br', 'c', 'ch', 'cr', 'chr', 'cl', 'ck', 'd', 'dr', 'f',
            'fl', 'g', 'gl', 'gr', 'h', 'j', 'k', 'l', 'll', 'm', 'n', 'p', 'ph',
            'pl', 'pr', 'q', 'r', 's', 'sc', 'sch', 'sh', 'sl', 'sp', 'st', 't',
            'th', 'thr', 'tr', 'v', 'w', 'wr', 'x', 'y', 'z'
        ]

        vowel_regex = '({})'.format('|'.join(vowels))
        consonant_regex = '({})'.format('|'.join(consonants))

        self.pronouncable_regex = RegEx((r'^{1}?{1}?({0}+{1}{1}?)*{0}*$'.format(vowel_regex, consonant_regex)).encode(), flags=IGNORECASE)

    def get_weights(self, match, content):
        # We populate the weights with generic ones first.
        weights = super().get_weights(match, content)

        data = match.group()
        average = get_average_byte(data)

        if average <= 95 and average >= 65:
            weights.append({
                'description': 'Similar byte average',
                'vector': 'Base64',
                'value': 0.125
            })
        else:
            weights.append({
                'description': 'Distant byte average',
                'vector': 'Base64',
                'value': -0.5
            })

        match_start, _ = match.span()
        last_line_index = content[:match_start].rfind(b'\n')
        line_content = content[last_line_index:match_start].upper()

        if b'HASH' in line_content or b'SHA' in line_content or b'MD5' in line_content:
            weights.append({
                'description': 'Potential hash',
                'vector': 'HexToken',
                'value': -0.25
            })

        pronouncable = 0
        unpronouncable = 0

        for word in find_all(b'[a-z0-9]+', data, flags=IGNORECASE):
            if self.pronouncable_regex.fullmatch(word):
                pronouncable += 1
            else:
                unpronouncable += 1

        for word in find_all(b'[A-Z]?[a-z]*', data):
            if len(word) <= 3:
                unpronouncable += 1
                continue

            if self.pronouncable_regex.fullmatch(word):
                pronouncable += 1
            else:
                unpronouncable += 1

        if pronouncable > unpronouncable:
            weights.append({
                'description': 'Pronouncable word',
                'vector': 'EntropyToken',
                'value': -0.25
            })
        else:
            weights.append({
                'description': 'Unpronouncable word',
                'vector': 'EntropyToken',
                'value': 0.25
            })

        try:
            b64decode(data + b'==')
        except BinaryError:
            weights.append({
                'description': 'Failed to decode with padding',
                'vector': 'Base64',
                'value': -0.125
            })

        try:
            b64decode(data, validate=True)
        except BinaryError:
            weights.append({
                'description': 'Failed to decode without padding',
                'vector': 'Base64',
                'value': -0.125
            })

        if data.isupper() or data.islower():
            weights.append({
                'description': 'All same case letters',
                'vector': 'Base64',
                'value': -0.5
            })
        else:
            weights.append({
                'description': 'Different cased letters',
                'vector': 'Base64',
                'value': 0.125
            })

        if data.endswith(b'==') or data.endswith(b'='):
            weights.append({
                'description': 'Ends with "=" or "=="',
                'vector': 'Base64',
                'value': 0.125
            })
        else:
            weights.append({
                'description': 'Does not end with "=" or "=="',
                'vector': 'Base64',
                'value': -0.125
            })

        if b'+' in data or b'/' in data:
            weights.append({
                'description': 'Contains "/" or "+"',
                'vector': 'Base64',
                'value': 0.125
            })
        else:
            weights.append({
                'description': 'Does not contain "/" or "+"',
                'vector': 'Base64',
                'value': -0.125
            })

        entropy = get_shannon_entropy(data)

        if b'ABCDEF' in data.upper():
            weights.append({
                'description': 'Contains alphabet sequence',
                'vector': 'HexToken',
                'value': -0.5 if b'GHIJKLMNOPQRSTUVWXYZ' in data.upper() else -0.25
            })

        if entropy > 3.75:
            weights.append({
                'description': 'High Shannon Entropy',
                'vector': 'Base64',
                'value': 0.125
            })
        else:
            weights.append({
                'description': 'Low Shannon Entropy',
                'vector': 'Base64',
                'value': -0.125
            })

        return weights
