#!/usr/bin/env python3
class Finding:
    @classmethod
    def get_indicators(this, context, context_start, context_end, capture, capture_start, capture_end, groups):
        return [['Capture matches pattern', 1]]


class SecretFinding(Finding):
    @classmethod
    def get_indicators(this, context, context_start, context_end, capture, capture_start, capture_end, groups):
        indicators = super().get_indicators(context, context_start, context_end, capture, capture_start, capture_end, groups)

        # We start by collecting the characters surrounding the capture.
        start_character = None

        if capture_start > 0:
            start_character = context[capture_start - 1]

        end_character = None

        if capture_end < len(context) - 1:
            end_character = context[capture_end]

        # We check whether the capture is the entirety of the file.
        if start_character == None and end_character == None:
            indicators.append(['Capture is the entire file', 1])
        # We check whether the capture is quoted or segmented.
        elif start_character != None and start_character == end_character:
            if start_character in b'\'"`':
                indicators.append(['Capture is quoted', 1])
            else:
                indicators.append(['Capture is segmented', 0.5])
        # We check whether the capture is at the start of a potentially-segmented file.
        elif (start_character == None and end_character in b',:|\t ') or \
        (end_character == None and start_character in b',:|\t '):
            indicators.append(['Capture appears segmented', 0.25])
        else:
            indicators.append(['Capture is not segmented', -0.5])

        return indicators
