#!/usr/bin/env python3

"""
find duplicate files.
# python 3.8.10
"""

import argparse
import collections
import datetime
import fnmatch
import functools
import hashlib
import itertools
import json
from numbers import Number
import operator
import os
import re
import sys
import time
from typing import Callable, Iterator, List, Sequence, Tuple, Union
import warnings


#
# Manage the 'strict' parameter of os.path.realpath (added since python 3.10)
#
vinfo = sys.version_info
if vinfo.major == 3 and vinfo.minor < 10:
    realpath = os.path.realpath
else:
    realpath = functools.partial(os.path.realpath, strict=True)

###############################################
# SOME CONSTANTS FOR PRUNE/COMPARE OPERATIONS #
###############################################

# see https://docs.python.org/3.8/library/os.html#os.stat_result
STAT_PRUNE_OPTIONS = {
    'uid':   'st_uid',      # User id of the owner.
    'gid':   'st_gid',      # Group id of the owner.
    'size':  'st_size',     # Size in bytes
    'atime': 'st_atime_ns', # Time of last access.
    'mtime': 'st_mtime_ns', # Time of last modification.
    'ctime': 'st_ctime_ns', # On some systems (like Unix) is the time of the
                            # last metadata change, and, on others
                            # (like Windows), is the creation time
                            # Note: using the _ns version for better precision
}

PRUNE_OPERATIONS_MAP = {
    '<': operator.lt,
    '<=': operator.le,
    '==': operator.eq,
    '>=': operator.ge,
    '>': operator.gt,
}

WARN_OPT = ('ignore', 'always', 'error')

DEFAULT_DEPTH = float('inf')

def showwarning (message, cat, fn, lno, *a, **k):
    print(message)
warnings.showwarning = showwarning


def frange (start: Number, stop: Number, step: Number=1) -> Iterator[Number]:
    """
    Range function yielding values from $start to $stop (excluded) by $step,
    supporting any Number arguments.
    """
    while start < stop:
        yield start
        start += step

def get_hash (path: str, hash_type: str ='sha224', size: int =2048) -> str:
    """
    Returns the hash of $path using $hash_type function.
    reading blocks of $size bytes of the file at a time.
    """
    with open(path, 'rb') as f:
        hashed = hashlib.new(hash_type)
        while True:
            buf = f.read(size)
            if not buf:
                break
            hashed.update(buf)
    return hashed.hexdigest()

def __ignore_inaccessible (paths): # XXX to del
    """Superseeded by check_real and check_regular functions."""
    for path in paths:
        try:
            os.stat(path)
            yield path
        except OSError as err:
            warnings.warn(f'{path} => {err}')

def expand_path (path: str) -> str:
    """Expands $path to the canonical form."""
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))

def find (basepath: str, depth: Union[int,float]) -> Iterator[str]:
    """Yields filenames from $basepath until $depth level."""
    for _, (subdir, _dirs, files) in zip(frange(0, depth), os.walk(basepath)):
        for filename in files:
            yield os.path.join(subdir, filename)

def check_real (path: str) -> Tuple[bool, str, Union[None, Exception]]:
    """
    Checks if realpath($path) == $path
    Returns (bool, realpath, None) or (False, None, raised exception).
    See note at https://docs.python.org/3.8/library/os.path.html#os.path.realpath
    """
    try:
        real_path = realpath(path)
        is_real = (real_path == path)
        return is_real, real_path, None
    except OSError as err:
        warnings.warn(f'{path} => {err}')        
        return False, None, err

def check_regular (path: str) -> bool:
    """
    Returns True if $path is a regular file and not a broken symlink nor
    a file for wich the user doesn't have enough permissions.
    """
    return os.path.exists(path) and os.path.isfile(path)

def prune_regular (paths: Sequence[str]) -> Iterator[str]:
    """Yield only regular $paths"""
    for path in paths:
        is_real, real_path, err = check_real(path)
        if is_real and check_regular(real_path):
            yield real_path

def _find_irregular (paths: Sequence[str]):
    raise NotImplementedError('to be written')
    #XXX+TODO: write a filter to find broken links or not stat-able files only

def prune_size (paths: Sequence[str], op: Callable, byte_size: int) -> Iterator[str]:
    """
    Prune by size.
    Yields filenames from $paths for which $op(path, $byte_size) is True.
    """
    for path in paths:
        if op(os.stat(path).st_size, byte_size):
            yield path
        
def prune_by_stat_attr (paths: Sequence[str],
                        op: Callable,
                        stat_attr: str,
                        value: Number) -> Iterator[str]:
    """
    Prune by stat attribute.
    Yields filenames from $paths for which $op(path's $stat_attr, $value) is True.
    """
    for path in paths:
        if op(getattr(os.stat(path), stat_attr), value):
            yield path

def prune_pattern (paths: Sequence[str], patterns: Sequence[str]) -> Iterator[str]:
    """
    Prune by pattern.
    Yields paths from $paths which filename match any of the $patterns (using fnmatch).
    """
    for path in paths:
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                yield path
                break

def prune_regex (paths: Sequence[str], regex: Sequence[str]) -> Iterator[str]:
    """
    Prune with regex.
    Yields paths from $paths which whole path match any of the $regex pattern
    using the re.match() function.
    """
    compiled_re = [re.compile(r) for r in regex]
    for path in paths:
        for prog in compiled_re:
            if prog.match(path):
                yield path
                break

    
def checksum (paths: Sequence[str], hash_func_name: str) -> dict:
    """
    Do checksum of path in $paths using hashlib's $hash_func_name.
    Returns a dict.
    """
    dd = collections.defaultdict(list)
    for path in paths:
        try:
            _hash = get_hash(path, hash_func_name)
            dd[_hash].append(path)
        except (OSError, PermissionError) as err:
            warnings.warn(f'get_hash: {path} => {err}')
    return dd

def filter_dup (result_dict: dict) -> dict:
    """Yields tuples of (hash, list_of_filenames_with_the_same_hash)."""
    return dict((hash_, files) for hash_, files in result_dict.items() if len(files) > 1)


###############################
# MAIN AND CMDLINE PROCEDURES #
###############################

def get_parser ():
    parser = argparse.ArgumentParser(description='Find duplicate files.')
    parser.add_argument('paths',
                        type=str, nargs='*', default=[os.getcwd()],
                        metavar='PATH',
                        help='Search files in %(metavar)s(s).')
    parser.add_argument('-d', '--depth', 
                        dest='depth', type=int, default=DEFAULT_DEPTH,
                        metavar='N',
                        help='''Descends at most %(metavar)s levels of directories.
                        Starting directory is at level 1.
                        %(metavar)s <= 0 means no limits (default).''')
    parser.add_argument('-H', '--hashfunc',
                        dest='hash', type=str,
                        choices=hashlib.algorithms_available, default='md5',
                        metavar='HASH_FUNC',
                        help='''Hash function to use on files, One of: {}.
                        '''.format(', '.join(hashlib.algorithms_available)))
    parser.add_argument('-w', '--warn',
                        dest='warn', choices=WARN_OPT, default='always',
                        help='''Set warning level: choose from "%(choices)s"
                        to ignore them (no output), always print warnings or
                        raise an error. Default to "%(default)s".''')
    # filtering:
    filter_group = parser.add_argument_group('filters')
    filter_group.add_argument('-s', '--size',
                        dest='size', action='append', nargs=2, default=[],
                        metavar=('OPERATOR', 'VALUE'),
                        help='''Check only files for which the expression
                         `filesize OPERATOR VALUE` match. For example
                         --size > 100 (VALUE in bytes) match only files greater than
                        100 bytes.. Available operators are {0}.'''.format(
                            ', '.join(PRUNE_OPERATIONS_MAP.keys())))
    filter_group.add_argument('-t', '--time',
                        dest='time', action='append', nargs=3, default=[],
                        metavar=('STAT_ATTR', 'OPERATOR', 'VALUE'),
                        help='''Check only files for which the expression
                         `STAT_ATTR OPERATOR VALUE` match. For example
                         -t atime > 1234300 . VALUE must be a numer or
                         a string suitable for datetime conversion
                         like "YEAR:MONTH:DAY:HOUR:MIN:SEC" (YEAR, MONTH and
                         DAY are required). Available operators are
                         {0}. Available attributes are: {1}.'''.format(
                            ', '.join(PRUNE_OPERATIONS_MAP.keys()),
                            ', '.join(('atime', 'mtime', 'ctime'))))
    filter_group.add_argument('-u', '--uid',
                        type=int, dest='uid',metavar='uid',
                        help='Check only files with the given UID.')
    filter_group.add_argument('-g', '--gid',
                        type=int, dest='gid', metavar='gid',
                        help='Check only files with the given GID.')
    filter_group.add_argument('-p', '--patterns',
                        nargs='+', dest='patterns', default=[],
                        type=str, metavar='PATTERN',
                        help='''Check only filenames which match %(metavar)ss
                        (using fnmatch).''')
    filter_group.add_argument('-r', '--regex',
                        nargs='+', dest='regex', default=[],
                        type=str, metavar='PATTERN',
                        help='''Check only whole paths which match %(metavar)ss
                        (using re.match() function).''')
    # output
    output_group = parser.add_argument_group('output')
    output_group.add_argument('-j', '--json',
                        dest='to_json', action='store_true',
                        help='''To be used with the -o option, save results in the json format
                        (for subsequent easy processing).''')
    meg = output_group.add_mutually_exclusive_group()
    meg.add_argument('-o', '--output-file',
                     dest='output', metavar='FILE',
                     help='output results to %(metavar)s. (default: stdout).')
    meg.add_argument('-a', '--append-file',
                     dest='append', metavar='FILE',
                     help='append results to %(metavar)s')
    return parser

def filter_size (paths, op_size_pairs):
    filtered = paths
    for op_name, str_val in op_size_pairs:
        try:
            val = int(str_val)
            op = PRUNE_OPERATIONS_MAP[op_name]
        except ValueError as e:
            raise TypeError('invalid argument for size: {}'.format(str_val))
        except KeyError as e:
            raise TypeError('invalid operator for size: {}'.format(op_name))
        filtered = prune_size(filtered, op, val)
    return filtered

def filter_time (paths, times_opts):
    filtered = paths
    for attr, op_name, str_val in times_opts:
        try:
            op = PRUNE_OPERATIONS_MAP[op_name]
        except KeyError as e:
            raise TypeError('invalid operator for time: {}'.format(op_name))
        try:
            assert attr in ('atime', 'ctime', 'mtime')
        except AssertionError as e:
            raise TypeError('invalid argument for time: {}'.format(attr))
        try:
            val = int(str_val)
        except ValueError as e:
            try:
                val = time.mktime(
                    datetime.datetime(
                        *map(int, str_val.split(':'))).timetuple())
            except (TypeError, ValueError) as e:
                raise TypeError(
                    'invalid time: {0}: {1}'.format(e, str_val))
        filtered = prune_by_stat_attr(filtered, op, STAT_PRUNE_OPTIONS[attr], val)
    return filtered


def _doit (args):
    to_find = []
    if args.depth <= 0:
        args.depth = DEFAULT_DEPTH
    for basepath in args.paths:
        all_paths = find(expand_path(os.path.join(os.getcwd(), basepath)), args.depth)
        regular = prune_regular(all_paths)
        filtered_p = prune_pattern(regular, args.patterns) if args.patterns else regular
        filtered_regex = prune_regex(filtered_p, args.regex) if args.regex else filtered_p
        filtered_size = filter_size(filtered_regex, args.size)
        filtered_time = filter_time(filtered_size, args.time)
        if args.gid is not None:
            filtered_gid = prune_by_stat_attr(filtered_time, operator.eq,
                                     STAT_PRUNE_OPTIONS['gid'], args.gid)
        else:
            filtered_gid = filtered_time
        if args.uid is not None:
            filtered_uid = prune_by_stat_attr(filtered_gid, operator.eq,
                                     STAT_PRUNE_OPTIONS['uid'], args.uid)
        else:
            filtered_uid = filtered_gid
        to_find.append(filtered_uid)
    """#XXXXXXX: compare with find from findutils: OK
    for path in itertools.chain(*to_find):
        print(path)
    sys.exit()#"""
    return checksum(itertools.chain(*to_find), args.hash)

def main ():
    parser = get_parser()
    args = parser.parse_args()
    warnings.simplefilter(args.warn)
    if args.append and args.to_json:
        warnings.warn('[BAD!] -j option ignored. To be used with -o only.')
    results = filter_dup(_doit(args))
    if args.output:
        outfile = open(args.output, 'w')
    elif args.append:
        outfile = open(args.append, 'a')
    else:
        outfile = sys.stdout
    if args.to_json and not args.append:
        json.dump(results, outfile)
    else:
        for hash_, files in results.items():
            print('hash: {0}\n{1}\n'.format(
                hash_, '\n'.join(files)), file=outfile)
    if outfile != sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()

