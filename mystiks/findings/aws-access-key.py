#!/usr/bin/env python3
from . import SecretFinding


class AmazonAccessKeyID(SecretFinding):
    name = 'Amazon Web Services (AWS) Access Key ID'

    description = [
        'Exposing an AWS access key to end users can have serious security implications. If an attacker gains access to the key, they can potentially use it to perform unauthorized actions on the associated AWS account. This can include accessing sensitive data, launching new instances, and modifying existing resources.',
        'It is important to keep AWS access keys and other credentials secure and to only provide access to authorized individuals or services. Best practices for securing AWS keys include rotating them frequently, using temporary keys when possible, and restricting access to only the necessary resources and permissions.'
    ]

    patterns = [
        r'A[SK]IA[A-Z2-7]{16}'
    ]

    ideal_rating = 3

    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups):
        indicators = super().get_indicators(context, capture, capture_start, capture_end, groups)

        access_key_id = capture.decode()

        # Based on research: https://awsteele.com/blog/2020/09/26/aws-access-key-format.html
        # It seems that the character set complies with RFC 4648's base 32 alphabet.
        base32_map = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', '0123456789abcdefghijklmnopqrstuv')
        offset_account_id = int(access_key_id[4:12].translate(base32_map), 32)
        account_id = 2 * (offset_account_id - 549755813888)

        if account_id > 0:
            indicators.append(('Calculated account ID appears valid', 1))
        else:
            indicators.append(('Calculated account ID is invalid', -1))

        return indicators


FINDINGS = [AmazonAccessKeyID]
