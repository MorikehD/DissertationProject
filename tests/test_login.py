import unittest
from app import app, db
from app.models import User
from werkzeug.security import generate_password_hash
from flask import get_flashed_messages

class TestLogin(unittest.TestCase):

    def setUp(self):
        # Set up an application context
        self.app = app
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Configure the Flask test client
        self.client = self.app.test_client()
        self.client.testing = True

        # Setup a temporary database
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        db.create_all()

        # Create a test user
        self.test_user = User(
            email='testuser@example.com',
            username='testuser',
            password=generate_password_hash('correctpassword', method='pbkdf2:sha256'),  # Correct method
            role='student'
        )
        db.session.add(self.test_user)
        db.session.commit()

    def tearDown(self):
        # Cleanup the database
        db.session.remove()
        db.drop_all()

        # Pop the application context
        self.app_context.pop()

    # Add your test methods here
    def test_valid_login(self):
        with self.client:
            response = self.client.post('/login', data=dict(
                email='testuser@example.com',
                password='correctpassword'
            ), follow_redirects=True)

            # Check if the user was redirected correctly and the page rendered
            self.assertEqual(response.status_code, 200)

            # Check for the flash message in the session
            messages = get_flashed_messages(with_categories=True)
            self.assertIn(('success', 'Login successful!'), messages)

            # Check for user session data
            with self.client.session_transaction() as sess:
                self.assertEqual(sess['user_id'], self.test_user.id)
                self.assertEqual(sess['username'], self.test_user.username)
                self.assertEqual(sess['role'], self.test_user.role)

            # Check if the username is displayed in the final rendered page
            self.assertIn(b'Welcome, testuser!', response.data)

    def test_invalid_login_wrong_password(self):
        response = self.client.post('/login', data=dict(
            email='testuser@example.com',
            password='wrongpassword'
        ), follow_redirects=True)

        self.assertIn(b'Login failed. Check your email and password and try again.', response.data)
        with self.client.session_transaction() as sess:
            self.assertNotIn('user_id', sess)
            self.assertNotIn('username', sess)
            self.assertNotIn('role', sess)
        self.assertIn(b'Login', response.data)

    def test_invalid_login_nonexistent_user(self):
        response = self.client.post('/login', data=dict(
            email='nonexistent@example.com',
            password='any_password'
        ), follow_redirects=True)

        self.assertIn(b'Login failed. Check your email and password and try again.', response.data)
        with self.client.session_transaction() as sess:
            self.assertNotIn('user_id', sess)
            self.assertNotIn('username', sess)
            self.assertNotIn('role', sess)
        self.assertIn(b'Login', response.data)

    def test_empty_password(self):
        response = self.client.post('/login', data=dict(
            email='testuser@example.com',
            password=''
        ), follow_redirects=True)

        self.assertIn(b'Login failed. Check your email and password and try again.', response.data)
        with self.client.session_transaction() as sess:
            self.assertNotIn('user_id', sess)
            self.assertNotIn('username', sess)
            self.assertNotIn('role', sess)
        self.assertIn(b'Login', response.data)

if __name__ == '__main__':
    unittest.main()
