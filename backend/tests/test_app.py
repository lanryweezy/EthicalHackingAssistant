import unittest
from flask_testing import TestCase
from app import app, ethical_hacking_assistant

class AppTest(TestCase):
    def create_app(self):
        app.config['TESTING'] = True
        return app

    def test_index_route(self):
        response = self.client.get('/')
        self.assert200(response)

    def test_nmap_helper_validation(self):
        nmap_helper = ethical_hacking_assistant.nmap_helper
        valid_target = "127.0.0.1"
        invalid_target = "not a valid target"

        self.assertTrue(nmap_helper.validate_target(valid_target)['valid'])
        self.assertFalse(nmap_helper.validate_target(invalid_target)['valid'])

if __name__ == '__main__':
    unittest.main()
