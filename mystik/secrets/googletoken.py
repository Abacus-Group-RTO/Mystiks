#!/usr/bin/env python3
from . import Secret, SecretExpression


class GoogleToken(Secret):
    def __init__(self):
        super().__init__(
            name='GoogleToken',
            expressions=[
                SecretExpression(r'AIza[A-Za-z0-9\-_]{35}', weight=1.75)
            ]
        )
