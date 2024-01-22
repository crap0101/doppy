#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
====================================================================
A "to be written" module for manage files (as remove useless ones)
after the use of doppy.py
Provides only some basic function, custom ones will be easily written
by the user to fit specific needs elaborating the json data gets
from a doppy.py run.
=========================
"""

import argparse
import json
import os
import re
import sys
import warnings

##############################
# CONSTANTS AND UTILITY CODE #
##############################

FILES_SEP = '#------'
DOPPY_BLOCK = '\n\n'
DOPPY_HASH_HEAD = '#hash: '
DOPPY_HASH_RE = f'^{DOPPY_HASH_HEAD}(\w+)'

def showwarning (message, cat, fn, lno, *a, **k):
    print(message, file=sys.stderr)
warnings.showwarning = showwarning


################
# ACTUAL FUNCS #
################

def get_map_json (fp):
    """
    Returns a mapping from the json file $fp.
    """
    with open(fp) as jfile:
        return json.load(jfile)

def get_map_txt (fp):
    """
    Returns a mapping from $fp.
    """
    data = {}
    pattern = re.compile(DOPPY_HASH_RE)
    with open(fp) as f:
        for block in f.read().split(DOPPY_BLOCK):
            hashline, *paths = block.splitlines()
            if (h := pattern.match(hashline)):
                data[h.group(1)] = paths
            else:
                raise ValueError("Bad file format: {}".format(block))
    return data

def check_paths (paths):
    """
    For each path in $paths yields tuples of (path, os.stat(path)).
    On error, either issues a warning or raises an error.
    """
    for f in paths:
        try:
            yield (f, os.stat(f))
        except FileNotFoundError as err:
            warnings.warn(f'[FAIL] {f} => {err}')
        except Exception as err: # for Windows
            warnings.warn(f'[FAIL] {f} => {err}')
                
def sort_by_time (mapping):
    """
    Yields tuples of file paths in descending order,
    using the st_mtime_ns attribute.
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

def delete_old_duples (seq):
    """
    Removes all but the newest duples from $seq, the object
    returned by *sort_by_time*.
    """
    for files in seq:
        last, *others = files
        for old in others:
            try:
                os.remove(old)
                warnings.warn(f'removing {old}')
            except FileNotFoundError as err:
                warnings.warn(f'[FAIL] {err}')

def print_text (mapping, out):
    """
    Prints $mapping data to $out file, in the same text format
    of a run of doppy.py. Can be used to transform data previously
    saved in the json format.
    """
    with open(out, 'w') as stream:
        for hash, paths in mapping.items():
            stream.write(f'{DOPPY_HASH_HEAD}{hash}\n')
            for path in paths:
                stream.write(f'{path}\n')
            stream.write('\n')

def print_json (mapping, out):
    """
    Prints $mapping data to $out file in the json format.
    Can be used to transform data previously saved in the
    default text format of a run of doppy.py.
    """
    with open(out, 'w') as stream:
        json.dump(mapping, stream)


#################################################################
# XXX+TODO: temporary functions to be written/edited/deleted... #
#################################################################

def _print_fmt (seq, sep=FILES_SEP):
    """print duples"""
    for s in seq:
        last, *others = s
        print('\n'.join((f'#{last}', *others)))
        print(sep)


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


###########
# PARSING #
###########

def get_parser():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('inputfile',
                        nargs='?', default=sys.stdin, metavar='FILE',
                        help='input file (default: stdin).')
    parser.add_argument('-j', '--json',
                        dest='is_json', action='store_true',
                        help='input is in the json format.')
    parser.add_argument('-J', '--to-json',
                        dest='to_json', action='store_true',
                        help="Transforms input data in the json format.")
    parser.add_argument('-o', '--output',
                        dest='output', default=sys.stdout, metavar='FILE',
                        help='output file (default: stdout).')
    parser.add_argument('-r', '--remove-old',
                        dest='remove_old', action='store_true',
                        help='remove all but the newest duplicated files.')
    parser.add_argument('-t', '--to-text',
                        dest='to_text', action='store_true',
                        help="""Transforms input data in the
                        doppy.py's default output text format.""")
    return parser


if __name__ == '__main__':
    # get rid of the annoyng DeprecationWarning about the imp module
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.simplefilter('always')

    parser = get_parser()
    args = parser.parse_args()
    if args.to_text and args.to_json:
        parser.error('requested output in both text and json format')

    # get the data from a previouly run of doppy.py and put it in a mapping
    source = (args.inputfile
                  if args.inputfile is not sys.stdin
                  else args.inputfile.fileno())
    out = (args.output
           if args.output is not sys.stdout
           else args.output.fileno())

    if args.is_json:
        data = get_map_json(source)
    else:
        data = get_map_txt(source)
    #print(data) ######
    if args.remove_old:
        delete_old_duples(sort_by_time(data))
    if args.to_text:
        print_text(data, out)
    elif args.to_json:
        print_json(data, out)

