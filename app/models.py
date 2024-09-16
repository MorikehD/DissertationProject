from app import db
from datetime import datetime
from flask_login import UserMixin
from sqlalchemy.orm import relationship
from flask import jsonify
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    topic_id = db.Column(db.Integer, db.ForeignKey('topic.id'), nullable=False)
    topic = db.relationship('Topic', back_populates='questions')
    answers = db.relationship('Answer', backref='question', lazy=True)
    upvotes = db.Column(db.Integer, default=0)
    downvotes = db.Column(db.Integer, default=0)
    comments = relationship('Comment', back_populates='question', lazy=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Reference to the user who posted the question
    user = db.relationship('User', backref='questions')

    def __repr__(self):
        return f"Question('{self.content}', 'Upvotes: {self.upvotes}', 'Downvotes: {self.downvotes}')"

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'student' or 'teacher'
    is_teacher = db.Column(db.Boolean, default=False)  
    comments = relationship('Comment', back_populates='author', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


class Topic(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    questions = db.relationship('Question', back_populates='topic')

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('answers', lazy=True))
    

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'question_id', name='_user_question_uc'),)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    approved = db.Column(db.Boolean, default=False)  # Track approval status
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    author = relationship('User', back_populates='comments')
    question = relationship('Question', back_populates='comments')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self):
        return f'<Notification {self.message}>'
    

def find_related_questions(input_text, topic_id):
    # Retrieve all questions from the topic
    questions = Question.query.filter_by(topic_id=topic_id).all()
    question_texts = [q.content for q in questions]
    
    if not question_texts:
        return []

    # Combine input with existing questions
    texts = [input_text] + question_texts

    # TF-IDF Vectorization
    vectorizer = TfidfVectorizer().fit_transform(texts)
    vectors = vectorizer.toarray()

    # Cosine similarity between the input and other questions
    cosine_similarities = cosine_similarity(vectors[0:1], vectors[1:]).flatten()

    # Get the most similar questions (above a certain threshold)
    related_question_indices = cosine_similarities.argsort()[-5:][::-1]
    
    # Filter based on a threshold 
    related_questions = [
        questions[i] for i in related_question_indices if cosine_similarities[i] > 0.2
    ]

    return related_questions