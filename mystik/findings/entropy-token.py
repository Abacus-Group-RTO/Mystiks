#!/usr/bin/env python3
from regex import match as match_regex

from . import SecretFinding, get_pronounceable_rating, \
    get_shannon_entropy, get_sequence_rating, get_character_counts


class EntropyToken(SecretFinding):
    name = 'Entropy Token'

    description = [
        'TODO: Add a description for entropy tokens.'
    ]

    patterns = [
        r'(?i)[a-z0-9_=\.\-\+?!@#$%^&*/:]{8,}'
    ]

    ideal_rating = 7

    @classmethod
    def should_filter_match(this, match):
        capture = match.capture.decode()

        # If the match is entirely a hex value, we filter it.
        if match_regex(r'(?i)^[a-f0-9]+$', capture):
            return True

        # If it could be a URL or path, we check it out.
        if '/' in capture:
            url_patterns = [
                # This should catch patterns that may not specify a TLD, but DO
                # specify some kind of protocol (e.g. https://, sftp://).
                r'(?i)^(?:[a-z0-9]+)?://(?:[a-z0-9\-\.]+)(?:/[a-z0-9\-\+_\.%/?&=\[\]{}#]*)?$',

                # This should catch patterns that may not specify a protocol, but
                # DO specify some kind of TLD (e.g. example.org).
                r'(?i)^(?:(?:[a-z0-9]+)?://)?(?:(?:[a-z0-9\-]+\.){1,}[a-z0-9\-]+)(?:/[a-z0-9\-\+_\.%/?&=\[\]{}#]*)?$'
            ]

            # If the match looks like a URL, we filter it.
            for pattern in url_patterns:
                if match_regex(pattern, capture):
                    return True

            # If the match looks like a path, we exclude it.
            if match_regex(r'(?i)^(?:[a-z0-9\-\+_\. =]+/?){1,}$', capture):
                return True

        # If the match appears to be some kind of sequence, we skip it.
        if get_sequence_rating(capture) > 0.5:
            return True

        return False

    @classmethod
    def get_entropy_indicators(this, capture):
        indicators = []
        entropy = get_shannon_entropy(capture)

        # This is the maximum offset to use in either direction.
        max_offset = 4

        # We use the range typically associated to the English language.
        max_entropy = 4.5
        min_entropy = 2.5
        entropy_difference = max_entropy - min_entropy
        entropy_middle = min_entropy + (entropy_difference / 2)

        if entropy >= max_entropy:
            indicators.append((f'Value has high Shannon entropy of {entropy:.4f}', max_offset))
        elif entropy <= min_entropy:
            indicators.append((f'Value has low Shannon entropy of {entropy:.4f}', -max_offset))
        else:
            factor = (entropy - entropy_middle) / entropy_difference
            indicators.append((f'Value has Shannon entropy of {entropy:.4f}', round(factor * max_offset, 2)))

        return indicators

    @classmethod
    def get_pronounceable_indicators(this, capture):
        indicators = []
        rating = get_pronounceable_rating(capture)

        # This is the maximum offset to use in either direction.
        max_offset = 2

        # These are meant to cap the ratings in either direction.
        max_rating = 1
        min_rating = 0.5

        difference = max_rating - min_rating
        middle = min_rating + (difference / 2)

        if rating >= max_rating:
            indicators.append((f'Value has a high pronounceable rating of {rating:.4f}', -max_offset))
        elif rating <= min_rating:
            indicators.append((f'Value has a low pronounceable rating of {rating:.4f}', max_offset))
        else:
            factor = (rating - middle) / difference
            indicators.append((f'Value has a pronounceable rating of {rating:.4f}', -round(factor * max_offset, 2)))

        return indicators

    @classmethod
    def get_character_count_indicators(this, capture):
        indicators = []
        letter_count, number_count, symbol_count = get_character_counts(capture)

        if len(capture) in (letter_count, number_count, symbol_count):
            indicators.append(('Value only contains one character type', -1))
        elif all((letter_count, number_count, symbol_count)):
            indicators.append(('Value contains all character types', 1))

        return indicators

    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups): # noqa: C901,E261
        indicators = super().get_indicators(context, capture, capture_start, capture_end, groups)

        capture = capture.decode()

        indicators += this.get_pronounceable_indicators(capture)
        indicators += this.get_entropy_indicators(capture)
        indicators += this.get_character_count_indicators(capture)

        return indicators


FINDINGS = [EntropyToken]
