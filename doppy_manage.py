#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
====================================================================
A "to be written" module for manage files (i.e. remove useless ones)
after the use of doppy.py
=========================
"""

import argparse
import json
import os
import sys
import warnings

FILES_SEP = '#------'

def showwarning (message, cat, fn, lno, *a, **k):
    print(message, file=sys.stderr)
warnings.showwarning = showwarning


def get_map (json_path):
    """
    Returns a mapping from the json file path $json_path.
    """
    with open(json_path) as jfile:
        return json.load(jfile)

def check_paths (paths):
    """
    For each path in $paths yields tuples of (path, os.stat(path)).
    On error, either issues a warning or raises an error.
    """
    for f in paths:
        try:
            stat_info = os.stat(f)
            yield (f, stat_info)
        except FileNotFoundError as err:
            warnings.warn(f'[FAIL] {f} => {err}')
        except Exception as err: # for Windows
            warnings.warn(f'[FAIL] {f} => {err}')
                
def sort_by_time (mapping):
    """
    Yields tuples of file paths in descending order,
    using the st_mtime_ns attribute
    """
    for key, values in mapping.items():
        file_and_stat = list(check_paths(values))
        if not file_and_stat:
            warnings.warn(f'[FAIL] Not founds: {values}')
        else:
            yield tuple(x[0] for x in sorted(
                file_and_stat,
                key=lambda fs: fs[1].st_mtime_ns,
                reverse=True))


def _print_fmt (seq, sep=FILES_SEP):
    """print duples"""
    for s in seq:
        last, *others = s
        print('\n'.join((f'#{last}', *others)))
        print(sep)

def _del_fmt (file_object):
    for line in file_object:
        _line = line.strip()
        if _line and (not _line.startswith('#')):
            try:
                os.remove(_line)
                #print(f'removing {_line}')
            except FileNotFoundError as err:
                warnings.warn(f'[FAIL] {err}')

def _assert_del (file_object, sep=FILES_SEP):
    for line in file_object:
        _line = line.strip()
        to_keep = _line.startswith('#')
        if _line and (not to_keep):
            try:
                os.stat(_line)
                warnings.warn(f'[FAIL] Not Removed => {_line}')
            except FileNotFoundError:
                pass
        elif to_keep and _line != sep:
            try:
                os.stat(_line[1:])
            except FileNotFoundError:
                warnings.warn(f'[FAIL] REMOVED! => {_line}')

def get_parser():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('inputfile',
                        nargs='?', default=sys.stdin, metavar='FILE',
                        help='input file (default: stdin).')
    parser.add_argument('-j', '--json',
                        dest='is_json', action='store_true',
                        help='input is in json format.')
    parser.add_argument('-o', '--output',
                        dest='output', default=sys.stdout, metavar='FILE',
                        help='output file (default: stdout).')
    return parser


if __name__ == '__main__':
    with warnings.catch_warnings(): # get rid of the annoyng DeprecationWarning about the imp module
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.simplefilter('always')

    parser = get_parser()
    args = parser.parse_args()
    print(args.inputfile, args.output, args.is_json)
    exit(9)
    #
    # TODO: argparse
    #
    
    #_print_fmt(sort_by_time(get_map(sys.argv[1]))) # if json
    with open(sys.argv[1]) as f:
        #_del_fmt(f)
        _assert_del(f)
