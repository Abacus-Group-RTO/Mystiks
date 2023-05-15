#!/usr/bin/env python3
from . import Secret, SecretExpression


class AmazonToken(Secret):
    def __init__(self):
        super().__init__(
            name='AmazonToken',
            expressions=[
                SecretExpression(r'ASIA[A-Z0-9]{16,128}', weight=1.5),
                SecretExpression(r'AKIA[A-Z0-9]{16,128}', weight=1.5)
            ]
        )


    def get_weights(self, match, content):
        # We populate the weights with generic ones first.
        weights = super().get_weights(match, content)

        data = match.group()

        if len(data) == 16:
            weights.append({
                'description': 'Default token size',
                'vector': 'AmazonToken',
                'value': 0.25
            })

        if data.isupper():
            weights.append({
                'description': 'All uppercase',
                'vector': 'AmazonToken',
                'value': 0.25
            })

        return weights
