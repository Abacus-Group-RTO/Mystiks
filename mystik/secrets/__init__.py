#!/usr/bin/env python3
from enum import Enum
from math import log as logarithm
from re import compile as RegEx


class SecretExpression:
    '''
    This is used not only describe a secret's match pattern, but also to store
    the weight of each pattern.
    '''
    def __init__(self, expression, flags=0, weight=1):
        self.expression = RegEx(expression.encode(), flags=flags)
        self.weight = weight

    def find_all(self, content):
        for match in self.expression.finditer(content):
            yield (match, self.weight)


class Secret:
    '''
    To make a secret, only 3 things are required:

    1. `name`: A name for the secret's type.
    2. `expressions`: A list of expressions that will match the secret.
    3. `severity`: A severity rating for the secret's type (based on `SecretSeverity` enum).

    Optionally, you may also override the `get_weights` method to provide more
    special-case logic for increasing or decreasing secret weights.
    '''
    def __init__(self, name, expressions):
        self.name = name
        self.expressions = expressions

    def get_weights(self, match, content):
        weights = []
        match_start, match_end = match.span()
        start_character = None
        end_character = None

        if match_start != 0:
            start_character = chr(content[match_start - 1])

        if match_end < len(content):
            end_character = chr(content[match_end])

        if start_character == end_character:
            if start_character in ('\'', '"', '`'):
                weights.append({
                    'description': 'Quoted match',
                    'vector': 'Generic',
                    'value': 0.5
                })
            else:
                weights.append({
                    'description': 'Segmented match',
                    'vector': 'Generic',
                    'value': 0.25
                })
        elif start_character == '>' and end_character == '<':
            weights.append({
                'description': 'Entity match',
                'vector': 'Generic',
                'value': 0.5
            })
        elif start_character in (None, '\n', ',') and end_character in (None, '\r', '\n', ','):
            weights.append({
                'description': 'Isolated match',
                'vector': 'Generic',
                'value': 0.25
            })
        else:
            weights.append({
                'description': 'Partial match',
                'vector': 'Generic',
                'value': -0.25
            })

        data = match.group()
        sequence_to_data_ratio = get_longest_sequence(data) / len(data)

        if sequence_to_data_ratio > 0.25:
            weights.append({
                'description': 'Predictable sequence',
                'vector': 'Generic',
                'value': -0.5 * sequence_to_data_ratio
            })

        return weights

    def find_all(self, content):
        for expression in self.expressions:
            for match, weight in expression.find_all(content):
                weights = [
                    {
                        'description': 'Matched',
                        'vector': 'Generic',
                        'value': weight
                    }
                ]

                weights += self.get_weights(match, content)

                yield (match, weights)


def get_average_byte(data):
    '''
    This returns the average byte value across the given binary string.
    '''
    return sum([byte for byte in data]) / len(data)


def get_shannon_entropy(data):
    '''
    This calculates the Shannon Entropy value of the given binary string.
    '''
    encountered = {}

    for byte in data:
        encountered[byte] = encountered.get(byte, 0) + 1

    unique_bytes = len(encountered)
    entropy = 0

    for byte, count in encountered.items():
        p = float(count / unique_bytes)
        entropy -= p * logarithm(p, 2)

    return entropy


def get_longest_sequence(data):
    '''
    This captures incremental or decremental sequences of bytes. It also catches
    repititions of byte values.
    '''
    last_byte = data[0]
    longest_sequence = 0
    current_sequence = 0

    for byte in data[1:]:
        if abs(last_byte - byte) <= 1:
            current_sequence += 1
        else:
            if longest_sequence < current_sequence:
                longest_sequence = current_sequence

            current_sequence = 0

        last_byte = byte

    return max(longest_sequence, current_sequence)

