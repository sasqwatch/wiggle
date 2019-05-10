import re


def parse(path):
    with open(path, 'r') as fp:
        for line in fp:
            stripped = line.strip()
            if not len(stripped) or re.match(r'^(#|\w+$)', stripped):
                continue

            yield stripped


if __name__ == "__main__":
    import sys
    parse(sys.argv[1])