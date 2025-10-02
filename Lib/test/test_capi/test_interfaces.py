import unittest
from test.support import import_helper


_testcapi = import_helper.import_module('_testcapi')


class InterfacesTest(unittest.TestCase):
    def test_interface_getattrwchar(self):
        fn = _testcapi.interface_getattrwchar(_testcapi, "interface_getattrwchar")
        self.assertIs(fn, _testcapi.interface_getattrwchar)

        with self.assertRaises(AttributeError):
            _testcapi.interface_getattrwchar(_testcapi, 'ϼўТλФЙ')
