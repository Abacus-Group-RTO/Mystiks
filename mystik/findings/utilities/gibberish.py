#!/usr/bin/env python3
from math import log, exp
from json import dumps as to_json, loads as from_json
from pathlib import Path
from regex import compile as RegEx, finditer


ACCEPTED_CHARACTERS = 'abcdefghijklmnopqrstuvwxyz '


positions = {character: index for index, character in enumerate(ACCEPTED_CHARACTERS)}

# pos = dict([(char, idx) for idx, char in enumerate(ACCEPTED_CHARS)])


def normalize(line):
    return [character.lower() for character in line if character.lower() in ACCEPTED_CHARACTERS]


def ngram(n, text):
    """Return all n-grams from l after normalizing."""
    filtered = normalize(text)

    for start in range(0, len(filtered) - n + 1):
        yield ''.join(filtered[start:start + n])


def train(filename='big.txt'):
    """Train a simple model."""
    k = len(ACCEPTED_CHARACTERS)
    counts = [[10 for _ in range(k)] for _ in range(k)]

    # Count transitions from the training file
    with open(filename, 'r') as f:
        for line in f:
            for a, b in ngram(2, line):
                counts[positions[a]][positions[b]] += 1

    for i, row in enumerate(counts):
        s = float(sum(row))
        for j in range(len(row)):
            row[j] = log(row[j] / s)

    # with open('model.json', 'w') as file:
    #     file.write(to_json({
    #         'counts': counts
    #     }))

    return counts


def get_gibberish_score(text, model):
    """Return the average transition probability of l using the model."""
    log_prob = 0.0
    transition_ct = 0

    for a, b in ngram(2, text):
        log_prob += model[positions[a]][positions[b]]
        transition_ct += 1

    return exp(log_prob / (transition_ct or 1))


_WORD_PATTERN = RegEx(r'(?:([A-Z]?[a-z]{2,}))|(?:([a-z]?[A-Z]{2,}))')


def is_gibberish(text, model, threshold=0.05, overall_threshold=0.5):
    """Detect if text is gibberish based on the model and threshold."""
    gibberish_rating = 0

    for match in _WORD_PATTERN.finditer(text):
        score = get_gibberish_score(text, model)

        # if score < threshold:
        #     gibberish_rating += len(match.group())

        # ratings.append((len(match), score))
        gibberish_rating += score * len(match.group())

    rating = gibberish_rating / len(text)

    # print(rating, '==>>', text)

    # if rating > threshold:
    # print(gibberish_rating, len(text), gibberish_rating / len(text), text)

    return rating < 0.015
    # return rating < 0.01


def load_model(path='gibberish.json'):
    with open(Path(__file__).parent / path, 'r') as file:
        model = from_json(file.read())['counts']

    return model


if __name__ == '__main__':
    model = train()
    while True:
        text = input("Enter a string (Ctrl+C to quit): ")
        print("Gibberish!" if is_gibberish(text, model) else "Looks fine.")
