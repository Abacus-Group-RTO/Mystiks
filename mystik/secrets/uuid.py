#!/usr/bin/env python3
from re import IGNORECASE

from . import Secret, SecretExpression, get_average_byte


class UUID(Secret):
    def __init__(self):
        super().__init__(
            name='UUID',
            expressions=[
                # This captures anything that looks like a UUID, regardless of version.
                SecretExpression(r'[a-z0-9]{8}\-([0-9a-z]{4}\-){3}[0-9a-z]{12}', flags=IGNORECASE, weight=1.5)
            ]
        )

    def get_weights(self, match, content):
        # We populate the weights with generic ones first.
        weights = super().get_weights(match, content)

        data = match.group()
        average = get_average_byte(data.replace(b'-', b''))

        # numbers = '0123456789'
        # lowercase_letters = 'abcdef'
        # uppercase_letters = lowercase_letters.upper()
        # alphabet_size = len(lowercase_letters) + len(numbers)

        # lower_average = sum([ord(character) for character in lowercase_letters + numbers]) / alphabet_size
        # upper_average = sum([ord(character) for character in uppercase_letters + numbers]) / alphabet_size

        lower_average = 70.125
        upper_average = 58.125

        lower_average_distance = abs(average - lower_average)
        upper_average_distance = abs(average - upper_average)

        closest_distance = min(lower_average_distance, upper_average_distance)

        if closest_distance <= 10:
            weights.append({
                'description': 'Similar byte average',
                'vector': 'UUID',
                'value': 0.25 * (1 - (closest_distance / 10))
            })
        else:
            weights.append({
                'description': 'Distant byte average',
                'vector': 'UUID',
                'value': -0.25
            })

        # If the string indicates version 1, 3, 4, or 5: it's most-likely a UUID.
        if chr(data[14]) in ('1', '3', '4', '5'):
            weights.append({
                'description': 'Known version',
                'vector': 'UUID',
                'value': 0.25
            })
        else:
            weights.append({
                'description': 'Unknown version',
                'vector': 'UUID',
                'value': -0.25
            })

        return weights
