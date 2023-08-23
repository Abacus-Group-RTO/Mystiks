#!/usr/bin/env python3
from math import log2
from pathlib import Path
from importlib import import_module


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
        # We check whether the capture is at the start of a potentially-segmented file.
        elif (start_character == None and end_character in b',:|\t ') \
                or (end_character == None and start_character in b',:|\t '):
            indicators.append(('Capture appears segmented', 0.25))
        else:
            indicators.append(('Capture is not segmented', -0.5))

        return indicators

    @staticmethod
    def calculate_entropy(string):
        # Create a dictionary to store the frequency of each character
        freq_dict = {}
        for char in string:
            if char in freq_dict:
                freq_dict[char] += 1
            else:
                freq_dict[char] = 1

        # Calculate the entropy
        entropy = 0
        total_chars = len(string)
        for count in freq_dict.values():
            probability = count / total_chars
            entropy += probability * log2(probability)

        return -entropy


# We automatically build out a list of available findings.
FINDINGS = []

for file in Path(__file__).parent.glob('*.py'):
    # We skip any files that my be internally used by Python.
    if file.name.startswith('__'):
        continue

    # We extend out the findings list with our types.
    FINDINGS.extend(import_module(f'mystik.findings.{file.stem}').FINDINGS)
