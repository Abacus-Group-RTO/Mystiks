#!/usr/bin/env python3
from base64 import standard_b64decode
from json import loads as from_json
from json.decoder import JSONDecodeError
from binascii import Error as BinError

from . import SecretFinding, get_pronounceable_rating, \
    get_shannon_entropy, get_sequence_rating, get_character_counts, \
    get_relative_shannon_entropy


class JSONWebToken(SecretFinding):
    name = 'JSON Web Token (JWT)'

    description = [
        'A JSON Web Token (JWT) is a widely used authentication mechanism that securely transmits information between parties. However, exposing a static JWT in a public-facing application can pose a significant security risk. If a malicious actor gains access to a static JWT, they could potentially impersonate an administrative user or service account, giving them unauthorized access to sensitive information or the ability to perform unauthorized actions on behalf of the user. Therefore, it is crucial to keep JWTs secure and refresh them regularly to minimize the impact of a potential security breach.'
    ]

    patterns = [
        r'(?i)([a-z0-9\-_]{3,})\.([a-z0-9\-_]{3,})\.([a-z0-9\-_]*)'
    ]

    ideal_rating = 6

    @classmethod
    def should_filter_match(this, match):
        capture = match.capture.decode()

        # If the match appears to be some kind of sequence, we skip it.
        if get_sequence_rating(capture) > 0.5:
            return True

        # We try to decode the header section first.
        try:
            header = from_json(standard_b64decode(match.groups[0] + b'==').decode())
        except:
            return True

        # We try to decode the data section next.
        try:
            data = from_json(standard_b64decode(match.groups[1] + b'==').decode())
        except:
            if not isinstance(header, dict) or not 'enc' in header:
                return True

        return False

    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups): # noqa: C901,E261
        indicators = super().get_indicators(context, capture, capture_start, capture_end, groups)
        is_encrypted = False

        # We try to parse the first chunk as a JWT header.
        try:
            json = standard_b64decode(groups[0] + b'==').decode()
            header = from_json(json)

            if isinstance(header, dict):
                indicators.append(('First segment is valid JSON', 1))

                if 'enc' in header:
                    is_encrypted = True

                if 'alg' in header:
                    indicators.append(('First segment contains expected JSON', 1))
                else:
                    indicators.append(('First segment does not contain expected JSON', -0.5))
            else:
                indicators.append(('First segment is not valid JSON object', -1))
        except (UnicodeDecodeError, BinError):
            indicators.append(('First segment is not valid unicode', -2))
        except JSONDecodeError:
            indicators.append(('First segment is not valid JSON', -2))

        # We move onto the second chunk, which should be either JSON data or
        # encrypted content. If the content is encrypted, we should have
        # been told so in the header.
        try:
            json = standard_b64decode(groups[1] + b'==').decode()
            payload = from_json(json)

            if isinstance(payload, dict):
                indicators.append(('Second segment is valid JSON', 1))

                if 'sub' in payload:
                    indicators.append(('Second segment contains a subject', 1))
                else:
                    indicators.append(('Second segment does not contain a subject', -0.5))
            else:
                indicators.append(('Second segment is not valid JSON object', -1))
        except (UnicodeDecodeError, BinError, JSONDecodeError):
            if is_encrypted:
                indicators.append(('Second segment appears to be encrypted', 1))
            else:
                indicators.append(('Second segment is not valid unicode or JSON', -1))

        # The third chunk is not always guaranteed to exist, but if it is
        # does, this chunk should be signature data.
        try:
            json = standard_b64decode(groups[2] + b'==').decode()
            from_json(json)
            indicators.append(('Third segment is valid JSON', -2))
        except (UnicodeDecodeError, BinError):
            indicators.append(('Third segment is not valid unicode', 0.5))
        except JSONDecodeError:
            indicators.append(('Third segment is not valid JSON', 0.5))

        return indicators


FINDINGS = [JSONWebToken]
