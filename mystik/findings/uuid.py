#!/usr/bin/env python3
from . import SecretFinding


class UUID(SecretFinding):
    name = 'Universally Unique Identifier (UUID)'

    description = [
        'A UUID, or universally unique identifier, is a 128-bit value used to uniquely identify information in computer systems. Sometimes, a UUID can be used as an API token, which is a security mechanism used to authenticate and authorize access to an API.',
        'However, it is a bad idea to expose API tokens to end users because it can lead to security vulnerabilities. If an API token is exposed, it can be used by anyone to access the API and potentially perform unauthorized actions. This can be especially dangerous if the API provides access to sensitive information or functionality. Therefore, it is important to keep API tokens secure and limit their exposure to only authorized users and systems.'
    ]

    patterns = [
        '(?i)[a-z0-9]{8}\-([0-9a-z]{4}\-){3}[0-9a-z]{12}'
    ]

    ideal_rating = 3

    @classmethod
    def get_indicators(this, context, context_start, context_end, capture, capture_start, capture_end, groups):
        indicators = super().get_indicators(context, context_start, context_end, capture, capture_start, capture_end, groups)

        # If the string indicates version 1, 3, 4, or 5: it's most-likely a UUID.
        if chr(capture[14]) in ('1', '3', '4', '5'):
            indicators.append(('Value specifies a known UUID version', 1))
        else:
            indicators.append(('Value does not specify a known UUID version', -0.5))

        return indicators
