import unittest
from flask import Flask, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from app import app, db
from app.models import User, Topic, Question, Answer

class TestQuestionPosting(unittest.TestCase):
 
    @classmethod
    def setUpClass(cls):
        cls.app = app
        cls.app.config['TESTING'] = True
        cls.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        cls.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        cls.client = cls.app.test_client()
        
        with cls.app.app_context():
            db.create_all()

            # Create test data
            cls.user = User(username='testuser', email='testuser@example.com', 
                            password=generate_password_hash('testpassword'), role='student')
            cls.topic = Topic(title='Test Topic')

            db.session.add(cls.user)
            db.session.add(cls.topic)
            db.session.commit()

            # Refresh the instances to attach them to the session
            db.session.refresh(cls.user)
            db.session.refresh(cls.topic)

    @classmethod
    def tearDownClass(cls):
        with cls.app.app_context():
            db.drop_all()

    def setUp(self):
        self.client = self.app.test_client()
        self.client.testing = True

    def test_post_question_as_logged_in_user(self):
        with self.client:
            # Log in the user by setting the session manually
            with self.client.session_transaction() as sess:
                with app.app_context():
                    # Re-fetch the user to ensure it's attached to the session
                    user = User.query.get(self.user.id)
                sess['user_id'] = user.id

            response = self.client.post(f'/topics/{self.topic.id}', data={
                'question': 'What is the new feature?',
                'question_id': '',
                'answer': ''
            }, follow_redirects=True)

            self.assertEqual(response.status_code, 200)
            self.assertIn(b'Question added!', response.data)
            
            # Check if the question was added to the database
            with app.app_context():
                new_question = Question.query.filter_by(content='What is the new feature?').first()
                self.assertIsNotNone(new_question)
                self.assertEqual(new_question.user_id, self.user.id)
                self.assertEqual(new_question.topic_id, self.topic.id)

    def test_post_question_as_guest(self):
        with app.app_context():
            # Re-fetch the topic to ensure it's attached to the session
            topic = Topic.query.get(self.topic.id)

        response = self.client.post(f'/topics/{topic.id}', data={
            'question': 'What is a guest user question?',
            'question_id': '',
            'answer': ''
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Question added!', response.data)

        # Check if the question was added to the database
        with app.app_context():
            new_question = Question.query.filter_by(content='What is a guest user question?').first()
            self.assertIsNotNone(new_question)
            self.assertIsNone(new_question.user_id)  # No user_id since it's a guest
            self.assertEqual(new_question.topic_id, topic.id)

if __name__ == '__main__':
    unittest.main()