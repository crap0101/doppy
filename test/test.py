
import os
import sys
import unittest

class TestFind (unittest.TestCase):
    def test_cmp (self):
        d = doppy.DEFAULT_DEPTH
        paths = []
        mp = os.path.dirname(os.path.abspath(__file__))
        for i in range(4):
            if len(mp) < 3:
                break
            paths.append(mp)
            mp = os.path.dirname(mp)
        for p in paths:
            o, n = map(tuple, (doppy._find(p, d), doppy.find(p, d)))
            self.assertEqual(o, n)
        for p in paths:
            for o, n in zip(doppy._find(p, d), doppy.find(p, d)):
                self.assertEqual(o,n)

if __name__ == '__main__':
    mp = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, mp)
    import doppy
    unittest.main()
