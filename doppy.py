#!/usr/bin/env python

# Copyright (C) 2022-2025 Marco Chieppa (aka crap0101)
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
from collections import defaultdict
from collections.abc import Callable, Container, Iterator, MutableSequence, Sequence
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from datetime import datetime
import hashlib
from itertools import chain
import json
from multiprocessing import Manager, Lock
import operator
import os
import re
import sys
from time import mktime
from typing import NewType


# external modules:
# https://github.com/crap0101/files_stuff
from files_stuff.filelist import find, FilelistWarning
from files_stuff.guid import uid_from_name, gid_from_name, name_from_uid, name_from_gid
from files_stuff.paths import expand_path
from files_stuff.paths import prune_regular, prune_regular_s
from files_stuff.paths import check_pattern, check_regex, check_stat_attr
from files_stuff.paths import exclude_pattern, exclude_regex
from files_stuff.paths import get_hash
from files_stuff.paths import PathWarning
from files_stuff.bytes_units import VariBaseBytes, BytesUnit
# https://github.com/crap0101/py_warnings
from py_warnings import pywarn
# https://github.com/crap0101/laundry_basket/blob/master/mismatched_socks.py
from mismatched_socks import frange


# PROGRAM'S INFO
__doc__ = """=====================
Find duplicate files.
# tested with python >= 3.10.12

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

Need the files_stuff package @ https://github.com/crap0101/files_stuff
and py_warning @ https://github.com/crap0101/py_warnings
"""

PROGNAME = 'doppy'
VERSION = '1.2'

# CUSTOM TYEPS
PPE = NewType('PPE', ProcessPoolExecutor)
TPE = NewType('TPE', ThreadPoolExecutor)

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

# see https://docs.python.org/3/library/os.html#os.stat_result
STAT_OPTIONS = {
    'uid':   'st_uid',      # User id of the owner.
    'gid':   'st_gid',      # Group id of the owner.
    'size':  'st_size',     # Size in bytes
    'atime': 'st_atime', # Time of last access.
    'mtime': 'st_mtime', # Time of last modification.
    'ctime': 'st_ctime', # On some systems (like Unix) is the time of the
                            # last metadata change, and, on others
                            # (like Windows), is the creation time
}

PRUNE_OPERATIONS_MAP = {
    '<': operator.lt,
    '<=': operator.le,
    '==': operator.eq,
    '>=': operator.ge,
    '>': operator.gt,
}


###################
# UTILITY CLASSES #
###################

class AppendExtendAction(argparse.Action):
    """
    for options with nargs > 1 repeated at command line and
    setting the default option's value  to [],
    appends each values' occurence as a sequence:
    --foo 2 3 4 => [[2,3,4]]
    --foo 2 3 4 --foo 5 6 7 => [[2,3,4],[5,6,7]]
    """
    def __call__(self, parser, namespace, values, option_string=None):
        old = getattr(namespace, self.dest)
        old.append(values)
        setattr(namespace, self.dest, old)

class MPAction:
    """Base class for or (Thread|Process)Pool"""
    def __init__(self, fun: Callable, proxy: Container):
        """
        A funtion to call and a container object
        (list, dict, wethever) to collect data based on
        the result of the function call.
        """
        self.fun = fun
        self.proxy = proxy


class MPAFilterT(MPAction):
    """For filtering operations using threads."""
    lock = None
    def __init__(self, fun: Callable, proxy: MutableSequence):
        self.fun = fun
        self.proxy = proxy
    def __call__(self, path: str):
        if self.fun(path):
            self.lock.acquire()
            self.proxy.append(path)
            self.lock.release()

class MPAFilterRegT(MPAFilterT):
    """For filtering regular files using threads."""
    def __call__(self, path: str):
        if (p := self.fun(path)):
            self.lock.acquire()
            self.proxy.append(p)
            self.lock.release()

class MPAGetHashT(MPAFilterT):
    """For pairing files and their hashes using threads."""
    def __call__(self, path: str):
        ret = self.fun(path)
        self.lock.acquire()
        if ret not in self.proxy:
            self.proxy[ret] = [path]
        else:
            self.proxy[ret].append(path) # = list(self.proxy[ret]) + [path]
        self.lock.release()

class MPAFilterP(MPAction):
    """For filtering operations using processes."""
    def __init__(self, fun: Callable, proxy: MutableSequence):
        self.fun = fun
        self.proxy = proxy
    def __call__(self, path: str):
        if self.fun(path):
            self.proxy.append(path)

class MPAFilterRegP(MPAFilterP):
    """For filtering regular files using processes."""
    def __call__(self, path: str):
        if (p := self.fun(path)):
            self.proxy.append(p)

class MPAGetHashP(MPAFilterP):
    """For pairing files and their hashes using processes."""
    def __call__(self, path: str):
        ret = self.fun(path)
        val = self.proxy.setdefault(ret, [path])
        if val != [path]:
            val.append(path)
            self.proxy[ret] = val
        """ # not faster:
        if ret not in self.proxy:
            self.proxy[ret] = [path]
        else:
            self.proxy[ret] = list(self.proxy[ret]) + [path]
        """


#################
# UTILITY FUNCS #
#################


def checksum (paths: Sequence[str], hash_func_name: str, size: int) -> dict:
    """
    Do checksum of each path in $paths using hashlib's $hash_func_name.
    Returns a dict of hash:[path, ...].
    """
    dd = defaultdict(list)
    for path in paths:
        try:
            _hash = get_hash(path, hash_func_name, size)
            dd[_hash].append(path)
        except (OSError, PermissionError) as err:
            pywarn.warn(PathWarning(f'get_hash: {path} => {err}'))
    return dd


def checksum_multi (fun: Callable,
                    paths: Sequence[str],
                    executor_type: PPE|TPE,
                    action_obj: MPAction,
                    chunk: int =PROCESSOR_CHUNK,
                    max_workers: int =MAX_WORKERS) -> dict:
    """
    Do checksum for each path in $paths with the given executor
    using $action_obj to execute $fun.
    Returns a dict.
    """
    with Manager() as manager:
        if hasattr(action_obj, 'lock'):
            d = dict()
        else:
            d = manager.dict()
        act = action_obj(fun, d)
        with executor_type(max_workers=max_workers) as executor:
            for _ in executor.map(act, paths, chunksize=chunk):
                pass
        if hasattr(action_obj, 'lock'):
            return d
        else:
            return dict(d)


def exec_multi(fun: Callable,
               paths: Sequence[str],
               executor_type: PPE|TPE,
               action_obj: MPAction,
               chunk: int =PROCESSOR_CHUNK,
               max_workers: int =MAX_WORKERS) -> list:
    """
    Executes some function for each path in $paths
    with the given executor using $action_obj to execute $fun.
    Returns a list.
    """
    with Manager() as manager:
        if hasattr(action_obj, 'lock'):
            lst = []
        else:
            lst = manager.list()
        act = action_obj(fun, lst)
        with executor_type(max_workers=max_workers) as executor:
            for _ in executor.map(act, paths, chunksize=chunk):
                pass
        if hasattr(action_obj, 'lock'):
            return lst
        else:
            return list(lst)


def exclude_pattern_m (patterns: Sequence[str]) -> Callable:
    """Returns a callable which match a given path against $patterns."""
    global exclude_pattern_inner
    def exclude_pattern_inner (path: str) -> bool:
        """
        Returns True if $path *not* match any of $patterns (use fnmatch).
        """
        return exclude_pattern(path, patterns)
    return exclude_pattern_inner


def exclude_pattern_s (paths: Sequence[str],
                       patterns: Sequence[str]) -> Iterator[str]:
    """
    Prune by pattern.
    Yields paths from $paths which *don't* match any of $patterns (use fnmatch).
    """
    for path in paths:
        if exclude_pattern(path, patterns):
            yield path


def exclude_regex_m (cregex: Sequence[re.Pattern]) -> Callable:
    """
    Returns a callable which tests a given path against $cregex.
    """
    global exclude_regex_inner
    def exclude_regex_inner (path: str) -> bool:
        return exclude_regex(path, cregex)
    return exclude_regex_inner


def exclude_regex_s (paths: Sequence[str],
                     cregex: Sequence[re.Pattern],
                     match_method='search') -> Iterator[str]:
    """
    Prune with regex.
    Yields paths from $paths which *not* match any of the $regex pattern,
    using re.Pattern.$match_method (default to 'search').
    """
    for path in paths:
        if exclude_regex(path, cregex, match_method):
            yield path


def filter_dup (result_dict: dict) -> dict:
    """
    Returns a dict of {hash: list_of_filenames_with_the_same_hash}
    excluding unique files.
    """
    return dict((hash_, files)
                for hash_, files in result_dict.items()
                if len(files) > 1)


def get_hash_m (hash_type_name: str, size: int) -> Callable:
    """
    Returns a callable which calculate the hash of the given file
    using hashlib.new($hash_type_name) and reading the file
    $size bytes at a time.
    """
    global get_hash_inner
    def get_hash_inner(path: str):
        return get_hash(path, hash_type_name, size)
    return get_hash_inner



def prune_by_stat_attr_m (fun: Callable, triplets) -> Callable:
    """
    Returns a callable to check if the given $path has the $stat_attr
    attribute set to $value using $op as comparison function.
    """
    global prune_by_stat_attr_inner
    def prune_by_stat_attr_inner(path):
        return fun(check_stat_attr(path, *t) for t in triplets)
    return prune_by_stat_attr_inner


def prune_by_stat_attr_s (paths: Sequence[str],
                          fun: Callable, triplets) -> Iterator[str]:
    """
    Prune by stat attribute.
    Yields avery path from $paths for which
    $fun(check_stat_attr($op($stat_attr, $value))) is True.
    """
    for path in paths:
        if fun(check_stat_attr(path, *t) for t in triplets):
            yield path


def prune_pattern_m (patterns: Sequence[str]) -> Callable:
    """
    Returns a callable to checks if the given path
    matches any elements of $patterns (use fnmatch).
    """
    global prune_pattern_inner
    def prune_pattern_inner(path):
        return check_pattern(path, patterns)
    return prune_pattern_inner


def prune_pattern_s (paths: Sequence[str],
                     patterns: Sequence[str]) -> Iterator[str]:
    """
    Prune by pattern.
    Yields paths from $paths which match any elements of $patterns (use fnmatch).
    """
    for path in paths:
        if check_pattern(path, patterns):
            yield path


def prune_regex_m (cregex: Sequence[re.Pattern], match_method: str = 'search') -> Callable:
    """
    Returns a callable which checks if the given path matches
    any elements of $cregex using re.Pattern.$match_method (default to 'search').
    """
    global prune_regex_inner
    def prune_regex_inner (path) -> bool:
        return check_regex(path, cregex, match_method)
    return prune_regex_inner


def prune_regex_s (paths: Sequence[str],
                   cregex: Sequence[re.Pattern],
                   match_method: str = 'search') -> Iterator[str]:
    """
    Prune with regex.
    Yields paths from $paths which match any elements of $cregex,
    using re.Pattern.$match_method (default to 'search').
    """
    for path in paths:
        if check_regex(path, cregex, match_method):
            yield path


###############################
# MAIN AND CMDLINE PROCEDURES #
###############################

def get_parser () -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGNAME,
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    # positional
    parser.add_argument('paths',
                        type=str, nargs='*', default=[], metavar='PATH',
                        help='Search files in %(metavar)s(s). Default: $PWD.')
    # options
    parser.add_argument('-v', '--version',
                        action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('-d', '--depth', 
                        dest='depth', type=int,
                        metavar='N', default=DEFAULT_DEPTH,
                        help='''Descends at most %(metavar)s levels
                        of directories. Starting directory is at level 1.
                        %(metavar)s <= 0 means no limits (default).''')
    parser.add_argument('-H', '--hashfunc',
                        dest='hash', type=str,
                        default='md5', metavar='HASH_FUNC',
                        choices=hashlib.algorithms_available,
                        help='''Hash function to use on files, One of: {}.
                        Default to "%(default)s".
                        '''.format(', '.join(hashlib.algorithms_available)))
    parser.add_argument('-S', '--read-size',
                        dest='read_size', type=int,
                        default=READ_SIZE, metavar='SIZE',
                        help='''Reads files %(metavar)s bytes at a time.
                        If <= 0 reads files at once. Default: %(default)s''')
    parser.add_argument('-w', '--warn',
                        dest='warn', choices=pywarn.WARN_OPT, default='always',
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
                        dest='proc_chunk', type=int,
                         default=PROCESSOR_CHUNK, metavar='NUM',
                        help='''The chunks size which is submitedd to the pool
                        as separate tasks when using the multiprocessing -P
                        option. Default: %(default)s''')
    mr_group.add_argument('-m', '--max-workers',
                          dest='max_workers', type=int,
                          default=MAX_WORKERS, metavar='NUM',
                          help='''Use at most max_workers threads or processes
                          to execute calls asynchronously. Default to
                          %(default)s which means using default parameters
                          (see concurrent.futures documentation).''')
    # filtering:
    filter_group = parser.add_argument_group('filtering options')
    filter_group.add_argument('-s', '--size',
                              dest='size',  nargs=2, default=[],
                              action=AppendExtendAction,
                              metavar=('OPERATOR', 'VALUE'),
                              help='''Check only files for which the expression
                              `filesize OPERATOR VALUE` matches. For example
                              --size > 100 (VALUE in bytes) matches only files
                              greater than 100 bytes. Available operators are {0}.
                              Multiple options works like logical ANDs.
                              Values can be bare numbers or numbers with a suffix
                              as in 1000B, 12KB, etc. Legal suffix: {1}.
                              '''.format(', '.join(PRUNE_OPERATIONS_MAP.keys()),
                                         ', '.join(VariBaseBytes.UNIT_SYMBOLS)))
    filter_group.add_argument('--si',
                              dest='si_unit', action='store_true',
                              help='use powers of 1000 (not 1024) for the -s/--size option.')
    filter_group.add_argument('-t', '--time',
                              dest='time',  nargs=3, default=[],
                              action=AppendExtendAction,
                              metavar=('STAT_ATTR', 'OPERATOR', 'VALUE'),
                              help='''Check only files for which the expression
                              `STAT_ATTR OPERATOR VALUE` matches. For example
                              -t atime > 1234300 . VALUE must be a numer or
                              a string suitable for datetime conversion
                              like "YEAR:MONTH:DAY:HOUR:MIN:SEC" (YEAR, MONTH and
                              DAY are required). Available operators are
                              {0}. Available attributes are: {1}.
                              Multiple options works like logical ANDs.'''.format(
                                  ', '.join(PRUNE_OPERATIONS_MAP.keys()),
                                  ', '.join(('atime', 'mtime', 'ctime'))))
    filter_group.add_argument('-g', '--gid',
                              dest='gid', type=int, nargs='+', default=[],
                              action='extend', metavar='GID',
                              help='''Check only files with the given %(metavar)s.
                              Multiple options works like logical ORs.''')
    filter_group.add_argument('-G', '--groups',
                              dest='groups', nargs='+', default=[],
                              action='extend', metavar='GROUP',
                              help='''Check only files which %(metavar)s is the
                              group name of the owner.
                              Multiple options works like logical ORs.''')
    filter_group.add_argument('-u', '--uid',
                              dest='uid', type=int, nargs='+', default=[],
                              action='extend', metavar='uid',
                              help='''Check only files with the given UID.
                              Multiple options works like logical ORs.''')
    filter_group.add_argument('-U', '--users',
                              dest='users', nargs='+', default=[],
                              action='extend', metavar='USER',
                              help='''Check only files owned by the given %(metavar)s.
                              Multiple options works like logical ORs.''')
    filter_group.add_argument('-p', '--patterns',
                              dest='patterns', nargs='+', default=[],
                              action='extend', metavar='PATTERN',
                              help='''Check only filenames which match %(metavar)ss
                              (use fnmatch). Multiple options works like logical ORs.''')
    filter_group.add_argument('-r', '--regex',
                              dest='regex', nargs='+', default=[],
                              action='extend', metavar='PATTERN',
                              help='''Check only whole paths which match %(metavar)ss
                              (use re.search). Multiple options works like logical ORs.''')
    filter_group.add_argument('-e', '--exclude',
                              dest='exclude_patterns', nargs='+', default=[],
                              action='extend', metavar='PATTERN',
                              help='''Exclude filenames which match %(metavar)ss
                              (use fnmatch). Multiple options works like logical ORs.''')
    filter_group.add_argument('-E', '--exclude-regex',
                              dest='exclude_regex', nargs='+', default=[],
                              action='extend', metavar='PATTERN',
                              help='''Exclude paths which match %(metavar)ss
                              (use re.search). Multiple options works like logical ORs.''')
    # output
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('-j', '--json',
                        dest='to_json', action='store_true',
                        help='''Saves the result in the json format for subsequent
                        easy processing. To be used with the -o option,
                        conflicts with the -a option.''')
    meg = output_group.add_mutually_exclusive_group()
    meg.add_argument('-a', '--append-file',
                     dest='append', metavar='FILE',
                     help='append to %(metavar)s (default is to use stdout)')
    meg.add_argument('-o', '--output-file',
                     dest='output', metavar='FILE',
                     help='outputs to %(metavar)s (default is to use stdout).')
    return parser


###################
# EXECUTING FUNCS #
###################

def doit_multi (args):
    to_find = []

    if args.use_thread:
        executor_type = ThreadPoolExecutor
        LOCK = Lock()
        MPAFilter = MPAFilterT
        MPAFilter.lock = LOCK
        MPAFilterReg = MPAFilterRegT
        MPAGetHash = MPAGetHashT
        MPAGetHash.lock = LOCK
    else:
        executor_type = ProcessPoolExecutor
        MPAFilter = MPAFilterP
        MPAFilterReg = MPAFilterRegP
        MPAGetHash = MPAGetHashP
    __exec_args = (executor_type, MPAFilter, args.proc_chunk, args.max_workers)
    __exec_reg_args = (executor_type, MPAFilterReg, args.proc_chunk, args.max_workers)
    __checksum_args = (executor_type, MPAGetHash, args.proc_chunk, args.max_workers)

    for basepath in args.paths:
        all_paths = find(expand_path(os.path.join(os.getcwd(), basepath)),
                         args.depth)
        regular = exec_multi(prune_regular, all_paths, *__exec_reg_args)
        filtered_ep = (exec_multi(exclude_pattern_m(args.exclude_patterns), regular, *__exec_args)
                       if args.exclude_patterns else regular)
        filtered_eregex = (exec_multi(exclude_regex_m(args.exclude_regex), filtered_ep, *__exec_args)
                          if args.exclude_regex else filtered_ep)
        filtered_p = (exec_multi(prune_pattern_m(args.patterns), filtered_eregex, *__exec_args)
                      if args.patterns else filtered_eregex)
        filtered_regex = (exec_multi(prune_regex_m(args.regex), filtered_p, *__exec_args)
                          if args.regex else filtered_p)
        filtered_size = (exec_multi(prune_by_stat_attr_m(all, args.size), filtered_regex, *__exec_args)
                         if args.size else filtered_regex)
        filtered_time = (exec_multi(prune_by_stat_attr_m(all, args.time), filtered_size, *__exec_args)
                         if args.time else filtered_size)
        if args.gid:
            filtered_gid = exec_multi(prune_by_stat_attr_m(any, args.gid),
                                      filtered_time,
                                      *__exec_args)
        else:
            filtered_gid = filtered_time
        if args.uid:
            filtered_uid = exec_multi(prune_by_stat_attr_m(any, args.uid),
                                      filtered_gid,
                                      *__exec_args)
        else:
            filtered_uid = filtered_gid
        to_find.append(filtered_uid)
    return checksum_multi(
        get_hash_m(args.hash, args.read_size),
        chain(*to_find), *__checksum_args)
    
def doit_nomulti (args):
    to_find = []
    for basepath in args.paths:
        all_paths = find(expand_path(os.path.join(os.getcwd(), basepath)),
                         args.depth)
        regular = prune_regular_s(all_paths)
        filtered_ep = (exclude_pattern_s(regular, args.exclude_patterns)
                       if args.exclude_patterns else regular)
        filtered_eregex = (exclude_regex_s(filtered_ep, args.exclude_regex)
                          if args.exclude_regex else filtered_ep)
        filtered_p = (prune_pattern_s(filtered_eregex, args.patterns)
                      if args.patterns else filtered_eregex)
        filtered_regex = (prune_regex_s(filtered_p, args.regex)
                          if args.regex else filtered_p)
        filtered_size = prune_by_stat_attr_s(filtered_regex, all, args.size) if args.size else filtered_regex
        filtered_time = prune_by_stat_attr_s(filtered_size, all, args.time) if args.time else filtered_size
        if args.gid:
            filtered_gid = prune_by_stat_attr_s(filtered_time, any, args.gid)
        else:
            filtered_gid = filtered_time
        if args.uid:
            filtered_uid = prune_by_stat_attr_s(filtered_gid, any, args.uid)
        else:
            filtered_uid = filtered_gid
        to_find.append(filtered_uid)
    return checksum(chain(*to_find), args.hash, args.read_size)


def main ():
    parser = get_parser()
    args = parser.parse_args()

    # set the warnings/errors behaviour
    pywarn.set_filter(args.warn, PathWarning)
    pywarn.set_filter(args.warn, FilelistWarning)
    pywarn.set_showwarning(pywarn.bare_showwarning)

    if not args.paths:
        print('NOTICE: No paths specified, using the current directory...', file=sys.stderr)
        args.paths.append(os.getcwd())

    if args.max_workers is not None and args.max_workers < 1:
        parser.error("max workers must be > 0")
    if args.depth < 0:
        args.depth = DEFAULT_DEPTH
    if args.read_size <= 0:
        args.read_size = -1
    if args.append and args.to_json:
        parser.error('OPTION CONFLICT: -j, -a.')

    try:
        _re_lst = []
        for r in args.regex:
            _re_lst.append(re.compile(r))
        args.regex = _re_lst
    except re.error as e:
        parser.error('malformed regex "{}": {}'.format(r, e))
    try:
        _re_lst = []
        for r in args.exclude_regex:
            _re_lst.append(re.compile(r))
        args.exclude_regex = _re_lst
    except re.error as e:
        parser.error('malformed regex "{}": {}'.format(r, e))
    __size = []
    try:
        for op_name, str_val in args.size:
            try:
                _b = BytesUnit(str_val, standard=VariBaseBytes)
                if args.si_unit:
                    _b.standard.convert_base(1000)
            except ValueError as e:
                parser.error(e)
            val = _b.bytes
            op = PRUNE_OPERATIONS_MAP[op_name]
            __size.append((op, STAT_OPTIONS['size'], val))
    except ValueError as e:
        raise TypeError('invalid argument for size: {}'.format(str_val)) from None
    except KeyError as e:
        raise TypeError('invalid operator for size: {}'.format(op_name)) from None
    args.size = __size

    __time = []
    for attr, op_name, str_val in args.time:
        try:
            op = PRUNE_OPERATIONS_MAP[op_name]
        except KeyError as e:
            raise TypeError('invalid operator for time: {}'.format(op_name)) from None
        try:
            assert attr in ('atime', 'ctime', 'mtime')
        except AssertionError as e:
            raise TypeError('invalid argument for time: {}'.format(attr)) from None
        try:
            val = int(str_val)
        except ValueError as e:
            try:
                val = mktime(
                    datetime(
                        *map(int, str_val.split(':'))).timetuple())
            except (TypeError, ValueError) as e:
                raise TypeError(
                    'invalid time: {0}: {1}'.format(e, str_val)) from None
        __time.append((op, STAT_OPTIONS[attr], val))
    args.time = __time

    # check gid/uid and groups/usernames:
    if args.groups:
        for g in args.groups:
            try: args.gid.append(gid_from_name(g))
            except KeyError: parser.error(f'Unknown group: {g}')
    for gid in args.gid:
        try: name_from_gid(gid)
        except KeyError:parser.error(f'Unknown gid: {gid}')
    if args.gid:
        args.gid = list((operator.eq, STAT_OPTIONS['gid'], g) for g in args.gid)
    # 
    if args.users:
        for u in args.users:
            try: args.uid.append(uid_from_name(u))
            except KeyError: parser.error(f'Unknown user: {u}')
    for uid in args.uid:
        try: name_from_uid(uid)
        except KeyError:parser.error(f'Unknown uid: {uid}')
    if args.uid:
        args.uid = list((operator.eq, STAT_OPTIONS['uid'], u) for u in args.uid)

    if args.use_thread or args.use_proc:
        results = filter_dup(doit_multi(args))
    else:
        results = filter_dup(doit_nomulti(args))

    # manage output:
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

