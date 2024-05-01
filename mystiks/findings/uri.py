#!/usr/bin/env python3
from . import SecretFinding


class URI(SecretFinding):
    name = 'Uniform Resource Identifier (URI)'

    description = [
        'A Uniform Resource Identifier (URI) is a string of characters that unambiguously identifies a particular resource. Typically, it encompasses both Uniform Resource Locators (URLs), which indicate where a resource can be found on the Internet, and Uniform Resource Names (URNs), which uniquely name a resource without specifying its location.',
        'In the context of searching for exposed secrets in code, URIs are crucial because they often serve as the direct pointers or references to remote resources, APIs, databases, and other critical components of software infrastructure. These identifiers can inadvertently include sensitive information such as access tokens, API keys, or database connection strings that, if discovered in public code repositories or logs, could lead to unauthorized access and significant security vulnerabilities.'
    ]

    patterns = [
        # This should catch patterns that may not specify a TLD, but DO
        # specify some kind of protocol (e.g. https://, sftp:// with
        # localhost, machine-01).
        r'(?i)(?:[a-z0-9]+)?://(?:[a-z0-9\-\.]+)(?:/[a-z0-9\-\+_\.%/?:&=\[\]{}#]*)?',

        # This should catch patterns that may not specify a protocol, but
        # DO specify some kind of TLD (e.g. example.org without
        # necessarily having https://).
        r'(?i)^(?:(?:[a-z0-9]+)?://)?(?:(?:[a-z0-9\-]+\.){1,}[a-z0-9\-]+)(?:/[a-z0-9\-\+_\.%/?:&=\[\]{}#]*)?$'
    ]

    ideal_rating = 3

    @classmethod
    def get_indicators(this, context, capture, capture_start, capture_end, groups):
        indicators = super().get_indicators(context, capture, capture_start, capture_end, groups)

        return indicators


FINDINGS = [URI]
