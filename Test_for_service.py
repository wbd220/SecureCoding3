import unittest
import requests
from bs4 import BeautifulSoup

server_address = "http://127.0.0.1:5000"


class FeatureTest(unittest.TestCase):

    def test_1_home_page_check(self):
        req = requests.get(server_address)
        self.assertEqual(req.status_code, 200)
        print("testing to see if there is a default page")

    def test_2_login_page_check(self):
        req = requests.get(server_address + "/login")
        self.assertEqual(req.status_code, 200)
        print("testing to see if /login page is there")

    def test_3_register_page_check(self):
        req = requests.get(server_address + "/register")
        self.assertEqual(req.status_code, 200)
        print("testing to see if /register page is there")

    def test_4_login_w_unregistered_account(self, session=None):
        login_result = None
        if session is None:
            session = requests.Session()
        getreq = session.get(server_address + "/login")
        soup = BeautifulSoup(getreq.text, features="html.parser")
        csrf_token = soup.find(id="csrf_token").get("value")
        print("csrf token is: ", csrf_token)
        reqdata = {"uname": "tester2", "pword": "password", "two_fa_field": "15553334444", "csrf_token": csrf_token}
        req = session.post(server_address + "/login", data=reqdata)
        soup = BeautifulSoup(req.text, features="html.parser")
        login_result = soup.find('div', id="result").text.strip().strip("\n")
        print("login_result is {}".format(login_result))
        assert login_result is not None
        self.assertEqual(login_result, "incorrect")

    def test_5_register_account(self, session=None):
        registration_result = None
        if session is None:
            session = requests.Session()
        getreq = session.get(server_address + "/register")
        soup = BeautifulSoup(getreq.text, features="html.parser")
        csrf_token = soup.find(id="csrf_token").get("value")
        print("csrf token is: ", csrf_token)
        reqdata = {"uname": "tester2", "pword": "password", "two_fa_field": "15553334444", "csrf_token": csrf_token}
        req = session.post(server_address + "/register", data=reqdata)
        soup = BeautifulSoup(req.text, features="html.parser")
        registration_result = soup.find('div', id="success").text.strip().strip("\n")
        print("registration_result is {}".format(registration_result))
        assert registration_result is not None
        self.assertEqual(registration_result, "success")

    def test_6_login_w_new_account(self, session=None):
        login_result = None
        if session is None:
            session = requests.Session()
        getreq = session.get(server_address + "/login")
        soup = BeautifulSoup(getreq.text, features="html.parser")
        csrf_token = soup.find(id="csrf_token").get("value")
        print("csrf token is: ", csrf_token)
        reqdata = {"uname": "tester2", "pword": "password", "two_fa_field": "15553334444", "csrf_token": csrf_token}
        req = session.post(server_address + "/login", data=reqdata)
        soup = BeautifulSoup(req.text, features="html.parser")
        login_result = soup.find('div', id="result").text.strip().strip("\n")
        print("login_result is {}".format(login_result))
        assert login_result is not None
        self.assertEqual(login_result, "success")

    def test_7_Spell_Check(self, session=None, just_the_words=None):
        spellcheck_result = None
        if session is None:
            session = requests.Session()
        # login before spell check
        getreq = session.get(server_address + "/login")
        soup = BeautifulSoup(getreq.text, features="html.parser")
        csrf_token = soup.find(id="csrf_token").get("value")
        reqdata = {"uname": "tester2", "pword": "password", "two_fa_field": "15553334444", "csrf_token": csrf_token}
        req = session.post(server_address + "/login", data=reqdata)
        print("logged in, checking spelling")
        # check spelling
        getreq = session.get(server_address + "/spell_check")
        soup = BeautifulSoup(getreq.text, features="html.parser")
        csrf_token = soup.find(id="csrf_token").get("value")
        print("csrf token is: ", csrf_token)
        reqdata = {"inputtext": "take a sad sogn and make it betta, let her under your skyn", "csrf_token": csrf_token}
        req = session.post(server_address + "/spell_check", data=reqdata)
        soup = BeautifulSoup(req.text, features="html.parser")
        spellcheck_result = soup.find('div', id="misspelled").text.strip().strip('\n')
        print("spellcheck_result result is\n {}".format(spellcheck_result))
        # assert spellcheck_result is not None
        self.assertEqual(spellcheck_result.count("sogn"), 1)
        self.assertEqual(spellcheck_result.count("betta"), 1)
        self.assertEqual(spellcheck_result.count("skyn"), 1)

    def test_8_register_account_wout_CSRF_Token(self, session=None):
        # in this test, not supplying CSRF token will cause Flask web service to ignore the post  i.e., no action
        registration_result = None
        if session is None:
            session = requests.Session()
        getreq = session.get(server_address + "/register")
        soup = BeautifulSoup(getreq.text, features="html.parser")
        csrf_token = soup.find(id="csrf_token").get("value")
        print("csrf token is: ", csrf_token)
        reqdata = {"uname": "tester3", "pword": "password", "two_fa_field": "33333333333"}  # no CSRF token passed!
        req = session.post(server_address + "/register", data=reqdata)
        soup = BeautifulSoup(req.text, features="html.parser")
        registration_result = soup.find('div', id="success").text.strip().strip("\n")  # should be blank  no script run
        print("registration_result is {}".format(registration_result))
        assert registration_result is not None
        self.assertEqual(registration_result, "")


if __name__ == '__main__':
    unittest.main()
