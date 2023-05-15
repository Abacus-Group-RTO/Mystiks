#!/usr/bin/env python3
from re import IGNORECASE

from . import Secret, SecretExpression, get_average_byte, get_shannon_entropy


class HexToken(Secret):
    def __init__(self):
        super().__init__(
            name='HexToken',
            expressions=[
                SecretExpression(r'[a-f0-9]{8,128}', flags=IGNORECASE, weight=0.75)
            ]
        )

    def get_weights(self, match, content):
        # We populate the weights with generic ones first.
        weights = super().get_weights(match, content)
        data = match.group()
        match_start, _ = match.span()

        last_line_index = content[:match_start].rfind(b'\n')
        line_content = content[last_line_index:match_start].upper()

        if b'HASH' in line_content or b'SHA' in line_content or b'MD5' in line_content:
            weights.append({
                'description': 'Potential hash',
                'vector': 'HexToken',
                'value': -0.25
            })

        if b'ABCDEF' in data.upper() or b'1234567890' in data:
            weights.append({
                'description': 'Contains alphabet sequence',
                'vector': 'HexToken',
                'value': -0.25
            })

        if match_start != 0:
            start_character = chr(content[match_start - 1])

        if start_character == '#':
            weights.append({
                'description': 'Similar to hex code',
                'vector': 'HexToken',
                'value': -0.125
            })

        average_byte = get_average_byte(data)

        average_entropy = 5.84
        average_entropy_breadth = 3.5
        shannon_entropy = get_shannon_entropy(data)
        entropy_distance = abs(average_entropy - shannon_entropy) / average_entropy_breadth

        if entropy_distance < 0.5:
            weights.append({
                'description': 'Similar Shannon Entropy',
                'vector': 'HexToken',
                'value': 0.125 - (0.125 * entropy_distance)
            })
        else:
            weights.append({
                'description': 'Dissimilar Shannon Entropy',
                'vector': 'HexToken',
                'value': -0.125 * entropy_distance
            })

        if data.isupper() or data.islower():
            weights.append({
                'description': 'All uppercase or all lowercase',
                'vector': 'HexToken',
                'value': 0.125
            })
        else:
            weights.append({
                'description': 'All uppercase or all lowercase',
                'vector': 'HexToken',
                'value': -0.125
            })

        if str(data.decode('unicode-escape')).isnumeric():
            weights.append({
                'description': 'All numbers',
                'vector': 'HexToken',
                'value': -0.5
            })

        expected_upper_average_distance = 10
        expected_lower_average_distance = 25
        lower_average_byte = 70.125
        upper_average_byte = 58.125

        lower_average_distance = abs(average_byte - lower_average_byte)
        upper_average_distance = abs(average_byte - upper_average_byte)

        if upper_average_distance <= expected_upper_average_distance:
            weights.append({
                'description': 'Similar uppercase byte average',
                'vector': 'HexToken',
                'value': 0.125 * (1 - (upper_average_distance / expected_upper_average_distance))
            })
        elif lower_average_distance <= expected_upper_average_distance:
            weights.append({
                'description': 'Similar lowercase byte average',
                'vector': 'HexToken',
                'value': 0.125 * (1 - (lower_average_distance / expected_lower_average_distance))
            })
        else:
            weights.append({
                'description': 'Dissimilar byte average',
                'vector': 'HexToken',
                'value': -0.125
            })

        data_length = len(data)

        if data_length < 16:
            weights.append({
                'description': 'Reasonable length',
                'vector': 'HexToken',
                'value': 0.125
            })
        elif data_length > 32:
            weights.append({
                'description': 'Unreasonable length',
                'vector': 'HexToken',
                'value': -0.25
            })

        return weights
