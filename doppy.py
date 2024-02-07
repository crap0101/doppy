#!/usr/bin/env python

# Copyright (C) 2022-2024 Marco Chieppa (aka crap0101)
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not see <http://www.gnu.org/licenses/>

import argparse
import collections
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import datetime
import fnmatch
import functools
import hashlib
import json
from multiprocessing import Manager, Lock
from numbers import Number
import operator
import os
import re
import sys
import time
from typing import Callable, Iterator, List, Sequence, Tuple, Union
import warnings

__doc__ = """=====================
Find duplicate files.
# python >= 3.8.10

Search for duplicated file on the given paths and write to file (or stdout)
the result in the following format: a line with the ash of a group of
duplicate files followed by the path of the duplicated files (one per line)
followed by an empty line, as like:
#hash: FILES_HASH
DUPLICATE_FILE_1_PATH
DUPLICATE_FILE_2_PATH
DUPLICATE_FILE_N_PATH

#hash: ANOTHER_FILES_HASH
DUP.....
DU......
===========================================================================
"""

PROGNAME = 'doppy'
VERSION = '1.0'

#
# Manage the 'strict' parameter of os.path.realpath (added since python 3.10)
#
vinfo = sys.version_info
if vinfo.major == 3 and vinfo.minor < 10:
    realpath = os.path.realpath
else:
    realpath = functools.partial(os.path.realpath, strict=True)


# WARNING OPTIONS
WARN_OPT = ('ignore', 'always', 'error')

################################
# MULTIPROC AND READ CONSTANTS #
################################

DEFAULT_DEPTH = float('inf')
READ_SIZE = 1024*64
PROCESSOR_CHUNK = 1000
MAX_WORKERS = None


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

class MPAction:
    """For (Thread|Process)Pool"""
    def __init__(self, fun, proxy):
        self.fun = fun
        self.proxy = proxy
    
class MPAFilterT(MPAction):
    def __init__(self, fun, rest_args, proxy):
        self.fun = fun
        self.rest_args = rest_args
        self.proxy = proxy
        # self.lock as class attribute
    def __call__(self, path):
        if list(self.fun([path], *self.rest_args)):
            self.lock.acquire()
            self.proxy.append(path)
            self.lock.release()

class MPAGetHashT(MPAFilterT):
    def __call__(self, path):
        ret = self.fun(path, *self.rest_args)
        self.lock.acquire()
        if ret not in self.proxy:
            self.proxy[ret] = [path]
        else:
            self.proxy[ret] = list(self.proxy[ret]) + [path]
        self.lock.release()

class MPAFilterP(MPAction):
    def __init__(self, fun, rest_args, proxy):
        self.fun = fun
        self.rest_args = rest_args
        self.proxy = proxy
    def __call__(self, path):
        if list(self.fun([path], *self.rest_args)):
            self.proxy.append(path)

class MPAGetHashP(MPAFilterP):
    def __call__(self, path):
        ret = self.fun(path, *self.rest_args)
        if ret not in self.proxy:
            self.proxy[ret] = [path]
        else:
            self.proxy[ret] = list(self.proxy[ret]) + [path]
        
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

def get_hash (path: str, hash_type: str, size: int) -> str:
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
    See: https://docs.python.org/3.8/library/os.path.html#os.path.realpath
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

def prune_size (paths: Sequence[str], op: Callable, byte_size: int,
                ) -> Iterator[str]:
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
                        value: Number,
                        ) -> Iterator[str]:
    """
    Prune by stat attribute.
    Yields filenames from $paths for which
    $op(path's $stat_attr, $value) is True.
    """
    for path in paths:
        if op(getattr(os.stat(path), stat_attr), value):
            yield path

def prune_pattern (paths: Sequence[str], patterns: Sequence[str],
                   ) -> Iterator[str]:
    """
    Prune by pattern.
    Yields paths from $paths which match any of the $patterns (use fnmatch).
    """
    for path in paths:
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern):
                yield path
                break

def exclude_pattern (paths: Sequence[str], patterns: Sequence[str]
                     ) -> Iterator[str]:
    """
    Prune by pattern.
    Yields paths from $paths which *not* match any of $patterns (use fnmatch).
    """
    for path in paths:
        if not any(fnmatch.fnmatch(path, pattern) for pattern in patterns):
            yield path

def prune_regex (paths: Sequence[str], regex: Sequence[str]
                 ) -> Iterator[str]:
    """
    Prune with regex.
    Yields paths from $paths which match any
    of the $regex pattern (use re.match).
    """
    compiled_re = [re.compile(r) for r in regex]
    for path in paths:
        for prog in compiled_re:
            if prog.match(path):
                yield path
                break

def exclude_regex (paths: Sequence[str], regex: Sequence[str]
                   ) -> Iterator[str]:
    """
    Prune with regex.
    Yields paths from $paths which *not* match any
    of the $regex pattern (use re.match).
    """
    compiled_re = [re.compile(r) for r in regex]
    for path in paths:
        if not any(prog.match(path) for prog in compiled_re):
            yield path

def checksum (paths: Sequence[str], hash_func_name: str, size: int) -> dict:
    """
    Do checksum of path in $paths using hashlib's $hash_func_name.
    Returns a dict.
    """
    dd = collections.defaultdict(list)
    for path in paths:
        try:
            _hash = get_hash(path, hash_func_name, size)
            dd[_hash].append(path)
        except (OSError, PermissionError) as err:
            warnings.warn(f'get_hash: {path} => {err}')
    return dd

def filter_dup (result_dict: dict) -> dict:
    """Returns a dict of {hash: list_of_filenames_with_the_same_hash}."""
    return dict((hash_, files)
                for hash_, files in result_dict.items() if len(files) > 1)


###############################
# MAIN AND CMDLINE PROCEDURES #
###############################

def get_parser ():
    parser = argparse.ArgumentParser(
        prog=PROGNAME,
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    # positional
    parser.add_argument('paths',
                        type=str, nargs='*', default=[os.getcwd()],
                        metavar='PATH',
                        help='Search files in %(metavar)s(s).')
    # options
    parser.add_argument('-v', '--version',
                        action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('-d', '--depth', 
                        dest='depth', type=int, default=DEFAULT_DEPTH,
                        metavar='N',
                        help='''Descends at most %(metavar)s levels
                        of directories. Starting directory is at level 1.
                        %(metavar)s <= 0 means no limits (default).''')
    parser.add_argument('-H', '--hashfunc',
                        dest='hash', type=str,
                        choices=hashlib.algorithms_available, default='md5',
                        metavar='HASH_FUNC',
                        help='''Hash function to use on files, One of: {}.
                        Default to "%(default)s".
                        '''.format(', '.join(hashlib.algorithms_available)))
    parser.add_argument('-S', '--read-size',
                          dest='read_size', type=int, default=READ_SIZE,
                        metavar='SIZE',
                        help='''Reads files %(metavar)s bytes at a time.
                        If <= 0 reads files at once. Default: %(default)s''')
    parser.add_argument('-w', '--warn',
                        dest='warn', choices=WARN_OPT, default='always',
                        help='''Set warning level: choose from "%(choices)s"
                        to ignore them (no output), always print warnings or
                        raise an error. Default to "%(default)s".''')
    # op opts:
    mr_group = parser.add_argument_group('processes/threads and read options')
    tm_group = mr_group.add_mutually_exclusive_group()
    tm_group.add_argument('-T', '--use-threads',
                        dest='use_thread', action='store_true',
                        help='''Use multithreading''')
    tm_group.add_argument('-P', '--use-processes',
                        dest='use_proc', action='store_true',
                        help='''Use multiprocessing''')
    mr_group.add_argument('-c', '--chunks',
                        dest='proc_chunk', type=int, default=PROCESSOR_CHUNK,
                        metavar='NUM',
                        help='''The chunks size which is submitedd to the pool
                        as separate tasks when using the multiprocessing -P
                        option. Default: %(default)s''')
    mr_group.add_argument('-m', '--max-workers',
                        dest='max_workers', type=int, default=MAX_WORKERS,
                        metavar='NUM',
                        help='''Use at most max_workers threads or processes
                        to execute calls asynchronously. Default to %(default)s
                        which means using default parameters
                        (see concurrent.futures documentation).''')
    # filtering:
    filter_group = parser.add_argument_group('filtering options')
    filter_group.add_argument('-s', '--size',
                        dest='size', action='append', nargs=2, default=[],
                        metavar=('OPERATOR', 'VALUE'),
                        help='''Check only files for which the expression
                         `filesize OPERATOR VALUE` match. For example
                         --size > 100 (VALUE in bytes) match only files
                        greater than 100 bytes.. Available operators are {0}.
                        '''.format(', '.join(PRUNE_OPERATIONS_MAP.keys())))
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
    filter_group.add_argument('-g', '--gid',
                        type=int, dest='gid', metavar='gid',
                        help='Check only files with the given GID.')
    filter_group.add_argument('-u', '--uid',
                        type=int, dest='uid',metavar='uid',
                        help='Check only files with the given UID.')
    filter_group.add_argument('-p', '--patterns',
                        nargs='+', dest='patterns', default=[],
                        type=str, metavar='PATTERN',
                        help='''Check only filenames which match %(metavar)ss
                        (use fnmatch).''')
    filter_group.add_argument('-r', '--regex',
                        nargs='+', dest='regex', default=[],
                        type=str, metavar='PATTERN',
                        help='''Check only whole paths which match %(metavar)ss
                        (use re.match).''')
    filter_group.add_argument('-e', '--exclude',
                        nargs='+', dest='exclude_patterns', default=[],
                        type=str, metavar='PATTERN',
                        help='''Exclude filenames which match %(metavar)ss
                        (use fnmatch).''')
    filter_group.add_argument('-E', '--exclude-regex',
                        nargs='+', dest='exclude_regex', default=[],
                        type=str, metavar='PATTERN',
                        help='''Exclude paths which match %(metavar)ss
                        (use re.match).''')
    # output
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('-j', '--json',
                        dest='to_json', action='store_true',
                        help='''Saves the result in the json format
                        for subsequent easy processing.
                        To be used with the -o option, conflicts with
                        the -a option.''')
    meg = output_group.add_mutually_exclusive_group()
    meg.add_argument('-a', '--append-file',
                     dest='append', metavar='FILE',
                     help='append to %(metavar)s (default is to use stdout)')
    meg.add_argument('-o', '--output-file',
                     dest='output', metavar='FILE',
                     help='outputs to %(metavar)s (default is to use stdout).')
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
        filtered = prune_by_stat_attr(filtered,
            op, STAT_PRUNE_OPTIONS[attr], val)
    return filtered


def exec_multi(fun, rargs, paths, executor_type, filter,
               chunk=PROCESSOR_CHUNK, max_workers=MAX_WORKERS):
    with Manager() as manager:
        lst = manager.list()
        act = filter(fun, rargs, lst)
        with executor_type(max_workers=max_workers) as executor:
            for _ in executor.map(act, paths, chunksize=chunk):
                pass
        return list(lst)

def checksum_multi(fun, rargs, paths, executor_type, filter,
               chunk=PROCESSOR_CHUNK, max_workers=MAX_WORKERS):
    with Manager() as manager:
        d = manager.dict()
        act = filter(fun, rargs, d)
        with executor_type(max_workers=max_workers) as executor:
            for _ in executor.map(act, paths, chunksize=chunk):
                pass
        return dict(d)

def doit_multi (args):
    to_find = set()

    if args.use_thread:
        executor_type = ThreadPoolExecutor
        LOCK = Lock()
        MPAFilter = MPAFilterT
        MPAFilter.lock = LOCK
        MPAGetHash = MPAGetHashT
        MPAGetHash.lock = LOCK
    else:
        executor_type = ProcessPoolExecutor
        MPAFilter = MPAFilterP
        MPAGetHash = MPAGetHashP
    __exec_args = (executor_type, MPAFilter, args.proc_chunk, args.max_workers)
    __checksum_args = (executor_type, MPAGetHash, args.proc_chunk, args.max_workers)
    
    for basepath in args.paths:
        all_paths = find(expand_path(os.path.join(os.getcwd(), basepath)),
                         args.depth)
        regular = exec_multi(prune_regular, [], all_paths, *__exec_args)
        filtered_ep = (exec_multi(exclude_pattern, [args.exclude_patterns], regular, *__exec_args)
                       if args.exclude_patterns else regular)
        filtered_eregex = (exec_multi(exclude_regex, [args.exclude_regex], filtered_ep, *__exec_args)
                          if args.exclude_regex else filtered_ep)
        filtered_p = (exec_multi(prune_pattern, [args.patterns], filtered_eregex, *__exec_args)
                      if args.patterns else filtered_eregex)
        filtered_regex = (exec_multi(prune_regex, [args.regex], filtered_p, *__exec_args)
                          if args.regex else filtered_p)
        filtered_size = (exec_multi(filter_size, [args.size], filtered_regex, *__exec_args)
                         if args.size else filtered_regex)
        filtered_time = (exec_multi(filter_time, [args.time], filtered_size, *__exec_args)
                         if args.time else filtered_size)
        if args.gid is not None:
            filtered_gid = exec_multi(
                    prune_by_stat_attr, [operator.eq, STAT_PRUNE_OPTIONS['gid'], args.gid],
                filtered_time,
                *__exec_args)
        else:
            filtered_gid = filtered_time
        if args.uid is not None:
            filtered_uid = exec_multi(
                    prune_by_stat_attr, [operator.eq, STAT_PRUNE_OPTIONS['uid'], args.uid],
                filtered_gid,
                *__exec_args)
        else:
            filtered_uid = filtered_gid
        to_find.update(filtered_uid)
    return checksum_multi(
        get_hash, [args.hash, args.read_size],
        to_find, *__checksum_args)
    
def doit_nomulti (args):
    to_find = set()
    for basepath in args.paths:
        all_paths = find(expand_path(os.path.join(os.getcwd(), basepath)),
                         args.depth)
        regular = prune_regular(all_paths)
        filtered_ep = (exclude_pattern(regular, args.exclude_patterns)
                       if args.exclude_patterns else regular)
        filtered_eregex = (exclude_regex(filtered_ep, args.exclude_regex)
                          if args.exclude_regex else filtered_ep)
        filtered_p = (prune_pattern(filtered_eregex, args.patterns)
                      if args.patterns else filtered_eregex)
        filtered_regex = (prune_regex(filtered_p, args.regex)
                          if args.regex else filtered_p)
        filtered_size = filter_size(filtered_regex, args.size) if args.size else filtered_regex
        filtered_time = filter_time(filtered_size, args.time) if args.time else filtered_size
        if args.gid is not None:
            filtered_gid = prune_by_stat_attr(
                filtered_time,
                operator.eq,
                STAT_PRUNE_OPTIONS['gid'],
                args.gid)
        else:
            filtered_gid = filtered_time
        if args.uid is not None:
            filtered_uid = prune_by_stat_attr(
                filtered_gid,
                operator.eq,
                STAT_PRUNE_OPTIONS['uid'],
                args.uid
                )
        else:
            filtered_uid = filtered_gid
        to_find.update(filtered_uid)
    return checksum(to_find, args.hash, args.read_size)


def main ():
    parser = get_parser()
    args = parser.parse_args()
    warnings.simplefilter(args.warn)

    if args.max_workers is not None and args.max_workers < 1:
        parser.error("max workers must be > 0")
    if args.depth <= 0:
        args.depth = DEFAULT_DEPTH
    if args.read_size <= 0:
        args.read_size = -1
    if args.append and args.to_json:
        parser.error('OPTION CONFLICT: -j, -a.')


    if args.use_thread or args.use_proc:
        results = filter_dup(doit_multi(args))
    else:
        results = filter_dup(doit_nomulti(args))

    if args.output:
        outfile = open(args.output, 'w')
    elif args.append:
        outfile = open(args.append, 'a')
    else:
        outfile = sys.stdout
    if args.to_json:
        json.dump(results, outfile)
    else:
        for hash_, files in results.items():
            print('#hash: {0}\n{1}\n'.format(
                hash_, '\n'.join(files)), file=outfile)
    if outfile != sys.stdout:
        outfile.close()


if __name__ == '__main__':
    main()

