import os
import sys
import logging


import coloredlogs
coloredlogs.install(level='DEBUG')


if __name__ == '__main__':
    if sys.platform != 'darwin':
        raise NotImplementedError('Currently macOS only')

    sys.path.append(os.getcwd())
    sys.path.append(os.path.join(os.getcwd(), 'web'))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'wiggle.settings')

    import django
    from django.conf import settings
    from django.core import management

    django.setup()

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='archive.db')
    parser.add_argument('--sysroot', default='/')
    parser.add_argument('--override', '-f',
                        dest='override', action='store_true')
    parser.add_argument('--block', dest="block_list")
    parser.add_argument('--rule', dest='rule_file', action='store_true')
    parser.add_argument('directories', nargs='+',
                        help='directories to scan', metavar="PATH")
    parser.set_defaults(rulefile=False)
    parser.set_defaults(override=False)
    args = parser.parse_args()

    if os.path.exists(args.db):
        print('[Warning] File "%s" already exist' % args.db)
        if args.override == True:
            print('[Warning] You\'ve chosen to override the file. Data may lost')
        else:
            print('[Warning] Use -f to override.')
            sys.exit(1)

    # initializa database
    settings.DATABASES['default']['NAME'] = args.db
    management.call_command('makemigrations')
    management.call_command('migrate')

    # start scan
    from search.models import MachO
    from agent.scanner import Scanner
    from agent.ruleparser import parse as parse_rule_file
    directories = args.directories
    if args.rule_file:
        directories = sum((list(parse_rule_file(filename))
                           for filename in args.directories), [])

    if args.block_list:
        block_list = parse_rule_file(args.block)
    else:
        from agent import config
        block_list = config.block_list

    scanner = Scanner(directories, MachO,
                      sysroot=args.sysroot, block_list=block_list)
    scanner.run()
    print('See %s' % args.db)
