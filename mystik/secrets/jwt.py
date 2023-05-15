#!/usr/bin/env python3
from re import IGNORECASE

from . import Secret, SecretExpression


class JWT(Secret):
    def __init__(self):
        super().__init__(
            name='JWT',
            expressions=[
                SecretExpression(r'[a-z0-9\-_]{8,}\.[a-z0-9\-_]{8,}\.([a-z0-9\-_]*)', flags=IGNORECASE, weight=1.5)
            ]
        )

    def get_weights(self, match, content):
        # We populate the weights with generic ones first.
        weights = super().get_weights(match, content)
        #data = match.group()

        if match.group(1) == b'':
            weights.append({
                'description': 'Missing signature',
                'vector': 'JWT',
                'value': -0.5
            })

        return weights
