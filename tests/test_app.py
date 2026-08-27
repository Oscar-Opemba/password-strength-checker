import unittest
from app import analyze

class TestPassword(unittest.TestCase):
    def test_common_password_is_weak(self):
        result = analyze({'password': 'password'})
        self.assertEqual(result['strength'], 'weak')
        self.assertTrue(result['suggestions'])

if __name__ == '__main__': unittest.main()
