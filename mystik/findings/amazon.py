#!/usr/bin/env python3
from . import SecretFinding


class AmazonToken(SecretFinding):
    name = 'Amazon Web Services (AWS) Token'

    description = [
        'Exposing an AWS token to end users can have serious security implications. If an attacker gains access to the token, they can potentially use it to perform unauthorized actions on the associated AWS account. This can include accessing sensitive data, launching new instances, and modifying existing resources.',
        'It is important to keep AWS tokens and other credentials secure and to only provide access to authorized individuals or services. Best practices for securing AWS tokens include rotating them frequently, using temporary tokens when possible, and restricting access to only the necessary resources and permissions.'
    ]

    patterns = [
        'A[SK]IA[A-Z0-9]{16}'
    ]
