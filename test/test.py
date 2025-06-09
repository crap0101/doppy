
# doppy.py test suite
# TODO: add more tests

import os
import sys
import random
import shutil
import tempfile
from typing import List
import unittest

def make_dirs (basedir='/tmp', number=3):
    """Returns $number path to temporary folders in $basedir."""
    return [tempfile.mkdtemp(dir=basedir) for _ in range(number)]

def make_files (basedir='/tmp', number=3):
    """Returns $number of path to temporary files in $basedir."""
    paths = []
    for _ in range(number):
        fd, path = tempfile.mkstemp(dir=basedir)
        os.close(fd)
        paths.append(path)
    return paths

def make_dtree (basedir='/tmp', depth=3, dirnum=3):
    """"Return a root directory path in $basedir and a list of subdirs
    in root, $dirnums for any level until depth."""
    root = tempfile.mkdtemp(dir=basedir)
    subdirs = []
    basedirs = [root]
    for _ in range(depth):
        tmpd = []
        for bd in basedirs:
            for _ in range(dirnum):
                d = tempfile.mkdtemp(dir=bd)
                tmpd.append(d)
        subdirs.extend(tmpd)
        basedirs = tmpd
    return root, subdirs

def make_ftree (basedir, number=5):
    """Create temporary files in basedir and any subdirs, $number per directory.
    Return the list of paths."""
    paths = []
    for dirname, _, __ in os.walk(basedir):
         paths.extend(make_files(basedir=dirname, number=number))
    return paths

def write_data (path: str, data: List[int]):
    """Write $data in file $path."""
    with open(path, 'w+b') as f:
        f.write(bytes(data))


def make_duplicate (paths, number=10):
    """Make $number random file from $paths duplicate, i.e. write the same data in them.
    Returns a list of duplicated paths."""
    paths = list(paths)
    assert len(paths) >= number, '[NOGOOD] len(paths) = {} => must be >= {}'.format(paths, number)
    random.shuffle(paths)
    dups = []
    data = list(random.randint(1, 100) for _ in range(1000))
    for _, path in zip(range(number), paths):
        write_data(path, data)
        dups.append(path)
    return dups

class TestFind (unittest.TestCase):
    def test_duplicate (self):
        class FakeArgs:
            depth = doppy.DEFAULT_DEPTH
            hash = 'md5'
            gid = uid = []
            read_size = 1024
            regex =  patterns = size = time = []
            exclude_patterns = exclude_regex = []
        args = FakeArgs()
        root, dirs = make_dtree(depth=3, dirnum=3)
        print('{}: root dir is => {}'.format(__file__, root))
        paths = make_ftree(root)
        dups = make_duplicate(paths, number=5)
        args.paths = [root]
        results = doppy.doit_nomulti(args)
        dup_hash = doppy.get_hash(dups[0], 'md5', args.read_size)
        filelist = results[dup_hash]
        self.assertEqual(len(filelist), len(dups))
        self.assertEqual(sorted(dups), sorted(filelist))
        shutil.rmtree(root)
        print('...temp paths deleted.')


if __name__ == '__main__':
    mp = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, mp)
    import doppy
    unittest.main()
