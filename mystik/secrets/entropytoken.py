#!/usr/bin/env python3
from re import compile as RegEx, findall as find_all, fullmatch, IGNORECASE

from . import Secret, SecretExpression, get_average_byte, get_shannon_entropy


COMMON_WORDS = [
    'TLS', 'ECDHE', 'PSK', 'CHACHA20', 'POLY1305', 'SHA256',
    'GCM', 'SHA384', 'AES', 'CBC', 'DHE', 'RSA', 'DH', 'DHE',
    'DSS', 'ECDSA'
]


class EntropyToken(Secret):
    def __init__(self):
        super().__init__(
            name='EntropyToken',
            expressions=[
                SecretExpression(r'[a-z0-9\-_]{24,}', flags=IGNORECASE, weight=0.25),
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
        match_start, _ = match.span()

        last_line_index = content[:match_start].rfind(b'\n')
        line_content = content[last_line_index:match_start].upper()

        for indicator in [b'SECRET', b'KEY', b'API', b'TOKEN', b'PASSWORD', b'CREDENTIAL']:
            indicator_start = line_content.rfind(indicator)

            if indicator_start == -1:
                continue

            distance = (match_start - last_line_index) - (indicator_start + len(indicator))

            if distance < 32:
                weights.append({
                    'description': 'Additional indicator',
                    'vector': 'EntropyToken',
                    'value': 0.5
                })

        numbers = len(find_all(rb'[0-9]', data))
        letters = len(find_all(rb'[a-z\-_]', data, flags=IGNORECASE))
        is_hex = fullmatch(rb'^[a-f0-9]+$', data, flags=IGNORECASE)

        if b'ABCDEF' in data.upper():
            weights.append({
                'description': 'Contains alphabet sequence',
                'vector': 'HexToken',
                'value': -0.5 if b'GHIJKLMNOPQRSTUVWXYZ' in data.upper() else -0.25
            })

        if is_hex:
            weights.append({
                'description': 'All hex characters',
                'vector': 'EntropyToken',
                'value': -5
            })

        is_uuid = fullmatch(rb'[a-z0-9]{8}\-([0-9a-z]{4}\-){3}[0-9a-z]{12}', data, flags=IGNORECASE)

        if is_uuid:
            weights.append({
                'description': 'Formatted as UUID',
                'vector': 'EntropyToken',
                'value': -5
            })

        pronouncable = 0
        unpronouncable = 0
        common_words = 0
        total_words = 0

        for word in find_all(b'[a-z0-9]+', data, flags=IGNORECASE):
            # if self.pronouncable_regex.fullmatch(word):
            #     pronouncable += 1
            # else:
            #     unpronouncable += 1

            if word.upper() in COMMON_WORDS:
                common_words += 1

            total_words += 1

        for word in find_all(b'[A-Z]?[a-z]*', data):
            if len(word) <= 3:
                # unpronouncable += 1
                continue

            if self.pronouncable_regex.fullmatch(word):
                pronouncable += 1
            else:
                unpronouncable += 1

        if total_words != 0 and common_words / total_words > 0.5:
            weights.append({
                'description': 'Mostly common words',
                'vector': 'EntropyToken',
                'value': -0.5
            })

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

        if numbers and letters:
            if numbers / letters < 0.1:
                weights.append({
                    'description': 'Low number-to-letter ratio',
                    'vector': 'EntropyToken',
                    'value': -0.25
                })
            else:
                weights.append({
                    'description': 'Mixed numbers and letters',
                    'vector': 'EntropyToken',
                    'value': 0.5
                })
        else:
            weights.append({
                'description': 'Only letters or numbers',
                'vector': 'EntropyToken',
                'value': -0.25
            })

        shannon_entropy = get_shannon_entropy(data)

        if shannon_entropy > 5.5:
            weights.append({
                'description': 'High Shannon Entropy',
                'vector': 'EntropyToken',
                'value': 0.375 * (shannon_entropy / 5.5)
            })
        else:
            weights.append({
                'description': 'Low Shannon Entropy',
                'vector': 'EntropyToken',
                'value': -0.25
            })

        if len(data) % 8 == 0:
            weights.append({
                'description': 'Multiple of 8',
                'vector': 'EntropyToken',
                'value': 0.25
            })

        return weights
