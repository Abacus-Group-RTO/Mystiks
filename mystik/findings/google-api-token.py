#!/usr/bin/env python3
from . import SecretFinding


class GoogleToken(SecretFinding):
    name = 'Google API Token'

    description = [
        'A Google API token is a unique key that allows a user or application to access specific Google APIs. It is used to authenticate and authorize requests to Google\'s services. Exposing a Google API token can allow an attacker to run up costs for the associated Google account by making unauthorized requests to the linked APIs. This can result in increased usage fees or limits, which can be especially problematic for applications with limited budgets or resources. Additionally, attackers could potentially use the exposed token to abuse the associated APIs, which can lead to service disruptions or other issues.'
    ]

    patterns = [
        r'AIza[A-Za-z0-9\-_]{35}'
    ]

    ideal_rating = 2


FINDINGS = [GoogleToken]
