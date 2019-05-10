import shlex


def parse_query(query):
    tokens = shlex.split(query)
    dsl = {'search': []}
    key = ''

    for token in tokens:
        if token.endswith(':'):
            key = token[:-1]
        else:
            value = token or ''
            if ':' in token:
                key, word = token.split(':', 1)
                value = word
            elif not key:
                key = 'search'

            if key in dsl:
                dsl[key].append(value)
            else:
                dsl[key] = [value]

            key = ''

    # if key:
    #     dsl[key] = ''

    return dsl
