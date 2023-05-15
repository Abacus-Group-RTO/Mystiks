#!/usr/bin/env python3
from pathlib import Path
from queue import Empty
from re import split
from uuid import uuid4 as UUID4


def to_unit_size(count):
    units = ('B', 'KB', 'MB', 'GB', 'TB')
    index = 0

    while count >= 1024 and index < len(units):
        count /= 1024
        index += 1

    return f'{round(count, 2)}{units[index]}'


def check_path(path, patterns):
    for pattern in patterns:
        if path.match(pattern):
            return True

    return False


def build_manifest(parent, exclusions=None, inclusions=None, max_size=None):
    manifest = []

    # We build out a search function within this function.
    # This allows recursive searching without needing to specify the arguments
    # on every recursion (since they're built-in to the function's definition).
    def search_directory(parent):
        for child in parent.iterdir():
            # We start by checking whether this child meets the exclusion list.
            if exclusions:
                is_excluded = check_path(child, exclusions)

                if is_excluded:
                    continue

            # If it's not excluded, we make sure it's included (if specified).
            if inclusions:
                is_included = check_path(child, inclusions)

                if not is_included:
                    continue

            # Once we get this far, the search can continue as normal.
            if child.is_dir():
                search_directory(child)
            elif child.is_file():
                file_size = child.stat().st_size

                if max_size and file_size > max_size:
                    continue

                manifest.append({
                    'path': child.resolve(),
                    'name': child.name,
                    'size': file_size
                })

    # Everything is defined, we make the call.
    search_directory(Path(parent))

    # Once the recursion is complete, the manifest list should be populated
    # with all the targeted files.
    return manifest


def secret_searcher(context, secrets):
    discovered_secrets = []

    while True:
        # We try to get the child, and if we can't, we break out.
        try:
            target = context.work_queue.get_nowait()
            target = target['path']
        except Empty:
            break

        # We read our file into memory for faster searching.
        with open(target, 'rb') as file:
            contents = file.read()
            contents_size = file.tell()

        # We begin the search!
        for secret in secrets:
            for match, weights in secret.find_all(contents):
                total_weight = sum(weight['value'] for weight in weights)

                # If the weight is too low, we skip it.
                if total_weight < 1:
                    continue

                # We estimate the line index.
                line = contents[:match.span()[0]].count(b'\n') + 1
                match_start, match_end = match.span()

                discovered_secrets.append({
                    'uuid': str(UUID4()),
                    'filePath': split(r'[\\/]', str(target)),
                    'fileSize': to_unit_size(contents_size),
                    'secretType': secret.name,
                    'secret': str(match.group().decode('unicode-escape')),
                    'weights': weights,
                    'totalWeight': total_weight,
                    'matchLine': line,
                    'matchStart': match_start,
                    'matchEnd': match_end
                })

    context.result_queue.put(discovered_secrets)
