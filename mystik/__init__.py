#!/usr/bin/env python3
from .secrets.base64 import Base64
from .secrets.uuid import UUID
from .secrets.hextoken import HexToken
from .secrets.entropytoken import EntropyToken
from .secrets.googletoken import GoogleToken
from .secrets.amazontoken import AmazonToken
from .secrets.jwt import JWT

DEFAULT_SECRETS = [
    Base64(),
    UUID(),
    HexToken(),
    EntropyToken(),
    GoogleToken(),
    AmazonToken(),
    # JWT()
]
