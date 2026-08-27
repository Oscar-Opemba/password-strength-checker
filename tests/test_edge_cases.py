import unittest
from app import analyze

class TestPasswordEdgeCases(unittest.TestCase):
    def test_rejects_oversized_input_and_common_secret(self):
        self.assertIn('error', analyze({'password':'x' * 1025}))
        result = analyze({'password':'password'})
        self.assertEqual(result['strength'], 'weak')
        self.assertIn('privacy', result)

if __name__ == '__main__': unittest.main()
