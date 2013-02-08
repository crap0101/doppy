#!/usr/bin/env python3

"""
find duplicate files.
"""

import os
import sys
import stat
import time
import hashlib
import fnmatch
import datetime
import argparse
import operator
import itertools
import collections


# some constants for prune/compare operations
STAT_PRUNE_OPTIONS = {
    'uid': stat.ST_UID,  # User id of the owner.
    'gid': stat.ST_GID,  # Group id of the owner.
    'size': stat.ST_SIZE, # Size in bytes
    'atime': stat.ST_ATIME, # Time of last access.
    'mtime': stat.ST_MTIME, # Time of last modification.
    'ctime': stat.ST_CTIME, # On some systems (like Unix) is the time of the
                            # last metadata change, and, on others
                            #(like Windows), is the creation time
    }
PRUNE_OPERATIONS_MAP = {
    '<': operator.lt,
    '<=': operator.le,
    '>=': operator.ge,
    '>': operator.gt,
    }
DEFAULT_DEPTH = float('inf')


def get_hash (file, hash_type='sha224', size=2048):
    with open(file, 'rb') as f:
        hash_ = hashlib.new(hash_type)
        while True:
            buf = f.read(size)
            if not buf:
                break
            hash_.update(buf)
    return hash_.hexdigest()

def ignore_inaccessible(paths):
    for path in paths:
        try:
            os.stat(path)
            yield path
        except OSError:
            pass
        
def find(basepath, depth):
    for subdir, _, files in os.walk(basepath):
        if len(list(
            filter(None, os.path.split(
                os.path.relpath(subdir, basepath))))) <= depth:
            for file in files:
                yield os.path.join(subdir, file)

def prune_size(paths, op, byte_size):
    for path in paths:
        if op(os.stat(path).st_size, byte_size):
            yield path
        
def prune_by_stat_attr(paths, op, stat_attr, value):
    for path in paths:
        if op(os.stat(path)[stat_attr], value):
            yield path

def prune_match(paths, patterns):
    for path in paths:
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                yield path
                break

def checksum(paths, hash_func_name):
    dd = collections.defaultdict(list)
    if hash_func_name not in hashlib.algorithms_available:
        raise TypeError('Unknown hash function "{}"'.format(hash_func_name))
    for path in paths:
        dd[get_hash(path, hash_func_name)].append(path)
    for hash_, files in dd.items():
        if len(files) > 1:
            yield hash_, files

def get_parsed(args=None):
    parser = argparse.ArgumentParser(description='find duplicate files.')
    parser.add_argument('-s', '--size',
                        dest='size', metavar=('OPERATOR', 'VALUE'),
                        action='append', nargs=2, default=[],
                        help='check only files for which the expression'
                        ' `filesize OPERATOR VALUE` match. For example'
                        ' --size > 100 (VALUE in bytes). Available operators'
                        ' are {0}'.format(', '.join(PRUNE_OPERATIONS_MAP.keys())))
    parser.add_argument('-t', '--time',
                        dest='time', action='append', nargs=3,
                        metavar=('STAT_ATTR', 'OPERATOR', 'VALUE'), default=[],
                        help='check only files for which the expression'
                        ' `STATT_ATTR OPERATOR VALUE` match. For example'
                        ' -t atime > 1234300 . VALUE must be a numer or'
                        ' a string suitable for datetime conversion'
                        ' like "YEAR:MONTH:DAY:HOUR:MIN:SEC" (YEAR, MONTH and'
                        ' DAY are required). Available operators are'
                        ' {0}. Available attributes are: {1}'.format(
                            ', '.join(PRUNE_OPERATIONS_MAP.keys()),
                            ', '.join(('atime', 'mtime', 'ctime'))))
    parser.add_argument('-u', '--uid',
                        type=int, dest='uid', metavar='uid',
                        help='check only files with the given UID')
    parser.add_argument('-g', '--gid',
                        type=int, dest='gid', metavar='gid',
                        help='check only files with the given GID')
    parser.add_argument('-H', '--hashfunc',
                        type=str, dest='hash', metavar='HASH_FUNC_NAME',
                        choices=hashlib.algorithms_available, default='md5',
                        help='hash function to use on files, One of:'
                        ' {}'.format(', '.join(hashlib.algorithms_available)))
    parser.add_argument('-d', '--depth', 
                        type=int, dest='depth',
                        default=DEFAULT_DEPTH, metavar='N',
                        help='Descend at most N (a non-negative integer)'
                        ' levels of directories')
    parser.add_argument('-p', '--patterns',
                        nargs='*', dest='patterns', default=[],
                        type=str, metavar='PATTERN',
                        help='check only files which match the pattern(s)'
                        ' provided (use fnmatch)')
    parser.add_argument('-P', '--paths',
                        type=str, dest='paths', metavar='PATH',
                        nargs='*', default=[os.getcwd()],
                        help='search files in PATH(S)')
    parser.add_argument('-m', '--merge',
                        action='store_true', dest='merge',
                        help='check file globally, i.e. in any PATH'
                        ' specified with the -P/--paths option.'
                        ' Default action is to check for duplicates'
                        ' independently for each path.')
    parser.add_argument('-i', '--ignore',
                        action='store_true', dest='ignore',
                        help='ignore non existent or inaccessible files')
    parser.add_argument('-o', '--output-file', dest='output', metavar='FILE',
                        help='output results on FILE.'
                        ' (default: write to stdout).')
    parser.add_argument('-a', '--append-file', dest='append', metavar='FILE',
                        help='append results on FILE')
    parser.add_argument('-q', '--quiet',
                        action='store_true', dest='quiet',
                        help='no output will be written.')
    return parser.parse_args(args or sys.argv[1:])

def main():
    opts = get_parsed()
    to_find = []
    if opts.append == opts.output and any((opts.output, opts.append)):
        raise TypeError('cannot append and output on'
                        ' the same file: {}'.format(opts.append))
    if opts.depth <= 0:
        raise TypeError('depth must be a positive number, not {}'.format(
            opts.depth))
    for p in opts.paths:
        gen = find(os.path.abspath(p), opts.depth)        
        if opts.ignore:
            gen = ignore_inaccessible(gen)
        if opts.patterns:
            gen = prune_match(gen, opts.patterns)
        for op, val in opts.size:
            try:
                _val = int(val)
                _op = PRUNE_OPERATIONS_MAP[op]
            except ValueError as e:
                raise TypeError('invalid argument for size: {}'.format(val))
            except KeyError as e:
                raise TypeError('invalid operator for size: {}'.format(op))
            gen = prune_size(gen, _op, _val)
        for attr, op, val in opts.time:
            try:
                _op = PRUNE_OPERATIONS_MAP[op]
            except KeyError as e:
                raise TypeError('invalid operator for time: {}'.format(op))
            try:
                assert attr in ('atime', 'ctime', 'mtime')
            except AssertionError as e:
                raise TypeError('invalid argument for time: {}'.format(attr))
            try:
                _val = int(val)
            except ValueError as e:
                try:
                    _val = time.mktime(
                        datetime.datetime(
                            *map(int, val.split(':'))).timetuple())
                except (TypeError, ValueError) as e:
                    raise TypeError(
                        'invalid time: {0}: {1}'.format(e, val))
            gen = prune_by_stat_attr(gen, _op, STAT_PRUNE_OPTIONS[attr], _val)
        if opts.gid is not None:
            gen = prune_by_stat_attr(gen, operator.eq,
                                     STAT_PRUNE_OPTIONS['gid'], opts.gid)
        if opts.uid is not None:
            gen = prune_by_stat_attr(gen, operator.eq,
                                     STAT_PRUNE_OPTIONS['uid'], opts.uid)
        to_find.append(gen)
    results = []
    if opts.merge:
        results.append(checksum(itertools.chain(*to_find), opts.hash))
    else:
        for g in to_find:
            results.append(checksum(g, opts.hash))
    outfiles = []
    if not opts.quiet:
        outfiles.append(sys.stdout
                         if not opts.output
                         else open(opts.output, 'w'))
        if opts.append:
            outfiles.append(open(opts.append, 'a'))
    for hash_, files in itertools.chain(*results):
        for f in outfiles:
            print('hash: {0}\n\t{1}\n'.format(
                hash_, '\n\t'.join(files)), file=f)
    for f in outfiles:
        if f != sys.stdout:
            f.close()

if __name__ == '__main__':
    main()

