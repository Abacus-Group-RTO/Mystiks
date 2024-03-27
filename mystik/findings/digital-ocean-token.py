#!/usr/bin/env python3
from . import SecretFinding


class DigitalOceanToken(SecretFinding):
    name = 'DigitalOcean Personal Access Token (PAT)'

    description = [
        "A DigitalOcean Personal Access Token (PAT) essentially serves as a substitute for a user's password, providing access to the DigitalOcean control panel functionalities and resources without requiring manual login each time. It's specifically designed to facilitate the automation of tasks such as creating and managing droplets, volumes, and other DigitalOcean services through scripts or third-party applications.",
        "Exposing a Personal Access Token can be highly problematic because it grants whoever possesses the token the same level of access to the DigitalOcean account as the original user. This could lead to unauthorized access to private resources, manipulation or deletion of critical infrastructure, and potential data breaches. Furthermore, if an attacker gains access to this token, they can incur substantial costs on the victim's account by spinning up resources without restraint. Therefore, it's crucial to keep these tokens secure and treat them with the same level of caution as one would with their account passwords, including regularly reviewing and rotating tokens to minimize the risk of exposure."
    ]

    patterns = [
        r'dop_v([0-9\._]+)_[a-f0-9]{64}'
    ]

    ideal_rating = 3

    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups): # noqa: C901,E261
        indicators = super().get_indicators(context, capture, capture_start, capture_end, groups)
        token_version = groups[0].decode()
        known_versions = ['1']

        if token_version in known_versions:
            indicators.append(('Token version is known', 1))
        else:
            indicators.append(('Token version is unknown', -1))

        return indicators


FINDINGS = [DigitalOceanToken]
