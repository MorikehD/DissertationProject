import os
from flask import jsonify, render_template, request, redirect, url_for, flash, session, request, abort
from app import app, db, login_manager
from app.models import Question, User, Topic, Answer, Vote, Comment, find_related_questions
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_login import login_required, current_user, logout_user, login_user
from app.nlp_utils import compute_similarity
import spacy
from app.utils import send_notification_email



@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        if not username or not email or not password or not role:
            flash('All fields are required', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Check your email and password and try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'teacher':
            flash('You need to be a logged-in teacher to perform this action.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/topics', methods=['GET', 'POST'])
def list_topics():
    if request.method == 'POST':
        if 'user_id' in session and session.get('role') == 'teacher':
            title = request.form.get('title')
            description = request.form.get('description')
            if title:
                new_topic = Topic(title=title, description=description)
                db.session.add(new_topic)
                db.session.commit()
                flash('Topic added!', 'success')
            else:
                flash('Title is required', 'danger')
        else:
            flash('Only logged-in teachers can create topics.', 'danger')
            return redirect(url_for('login'))
    
    topics = Topic.query.all()
    is_teacher = 'user_id' in session and session.get('role') == 'teacher'
    return render_template('topics.html', topics=topics, is_teacher=is_teacher)

# Load the spaCy model
nlp = spacy.load('en_core_web_md')

@app.route('/topics/<int:topic_id>', methods=['GET', 'POST'])
def topic_questions(topic_id):
    topic = Topic.query.get_or_404(topic_id)
    threshold = 0.95  # Set similarity threshold for manual check

    # Fetch questions and answers for display
    questions = Question.query.filter_by(topic_id=topic_id).order_by(Question.upvotes.desc()).all()
    questions_with_answers = []
    for question in questions:
        answers = Answer.query.filter_by(question_id=question.id).all()
        questions_with_answers.append((question, answers))
    
    similar_question = None

    if request.method == 'POST':
        content = request.form.get('question')
        question_id = request.form.get('question_id')
        answer_content = request.form.get('answer')

        # Handle question submission
        if content:
            # Check for similar questions using both manual check and TF-IDF vectorization
            related_questions = find_related_questions(content, topic_id)

            # Filter based on a similarity threshold
            for question in related_questions:
                similarity = compute_similarity(content, question.content)
                if similarity > threshold:
                    similar_question = question
                    similar_answers = Answer.query.filter_by(question_id=similar_question.id).all()
                    flash('A similar question has already been asked. Please check it out.', 'info')
                    return render_template('topic_questions.html', 
                                           topic=topic, 
                                           questions_with_answers=questions_with_answers, 
                                           similar_question=similar_question,
                                           similar_answers=similar_answers)
            
            # Determine user_id (optional if not logged in)
            user_id = session.get('user_id')  # None if user is not logged in

            # Create and save the new question
            new_question = Question(content=content, topic_id=topic_id, user_id=user_id)
            db.session.add(new_question)
            db.session.commit()

            # Return the new question as JSON if the request is AJAX
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True,
                    'new_question': {
                        'id': new_question.id,
                        'content': new_question.content
                    }
                })

            flash('Question added!', 'success')
            return redirect(url_for('topic_questions', topic_id=topic_id))
        
        # Handle answer submission
        elif question_id and answer_content and 'user_id' in session and session['role'] == 'teacher':
            answer = Answer(content=answer_content, question_id=question_id, user_id=session['user_id'])
            db.session.add(answer)
            db.session.commit()
            flash('Answer submitted!', 'success')
            return redirect(url_for('topic_questions', topic_id=topic_id))

    return render_template('topic_questions.html', 
                           topic=topic, 
                           questions_with_answers=questions_with_answers, 
                           similar_question=similar_question)


@app.route('/topics/<int:topic_id>/questions/<int:question_id>', methods=['GET', 'POST'])
def answer_question(topic_id, question_id):
    # Fetch the question and ensure it exists
    question = Question.query.get_or_404(question_id)

    if request.method == 'POST':
        # Check if the user is logged in and is a teacher
        if 'user_id' in session and session['role'] == 'teacher':
            content = request.form.get('answer')
            
            if content:
                # Save the answer to the database
                answer = Answer(content=content, question_id=question.id, user_id=session['user_id'])
                db.session.add(answer)
                db.session.commit()  # Commit the answer to get the answer ID if needed

                # Fetch the teacher's information
                teacher = User.query.get(session['user_id'])

                # Fetch the student who asked the question
                student = question.user

                # Check if the student is not anonymous
                if student:
                    # Send an email notification to the student if they are registered
                    subject = "Your question has been answered!"
                    body = f"Hi {student.username},\n\nYour question has been answered by {teacher.username}. You can check the answer here: {url_for('topic_questions', topic_id=topic_id, _external=True)}.\n\nBest regards,\nYour App Team"
                    send_notification_email(student.email, subject, body)
                    flash('Answer submitted and notification sent to the student.', 'success')
                else:
                    # Handle the case where the user is anonymous
                    flash('Answer submitted for an anonymous user. No notification sent.', 'info')
                
                return redirect(url_for('topic_questions', topic_id=topic_id))
            
            else:
                flash('No answer provided', 'danger')
        else:
            flash('You must be logged in as a teacher to answer questions', 'danger')
    
    # Redirect back to the topic's questions page after handling the POST request
    return redirect(url_for('topic_questions', topic_id=topic_id))


@app.route('/upvote/<int:question_id>', methods=['POST'])
def upvote(question_id):
    question = Question.query.get_or_404(question_id)
    voted_questions = session.get('voted_questions', [])
    
    if question.upvotes is None:
        question.upvotes = 0
        
    voted_questions = session.get('voted_questions', [])

    if question_id not in voted_questions:
        question.upvotes += 1
        voted_questions.append(question_id)
        session['voted_questions'] = voted_questions
        db.session.commit()
    
    return redirect(url_for('topic_questions', topic_id=question.topic_id))


@app.route('/downvote/<int:question_id>', methods=['POST'])
def downvote(question_id):
    question = Question.query.get_or_404(question_id)
    voted_questions = session.get('voted_questions', [])

    if question.downvotes is None:
        question.downvotes = 0
        
    voted_questions = session.get('voted_questions', [])
    
    if question_id not in voted_questions:
        question.downvotes += 1
        voted_questions.append(question_id)
        session['voted_questions'] = voted_questions
        db.session.commit()
    
    return redirect(url_for('topic_questions', topic_id=question.topic_id))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/comment/<int:question_id>', methods=['POST'])
def comment(question_id):
    if not request.form['content']:
        flash('Comment content cannot be empty.', 'danger')
        return redirect(url_for('topic_questions', topic_id=Question.query.get_or_404(question_id).topic_id))
    
    new_comment = Comment(
        content=request.form['content'],
        question_id=question_id,
        user_id=current_user.id if current_user.is_authenticated else None
    )
    db.session.add(new_comment)
    db.session.commit()
    flash('Comment submitted and is awaiting approval.', 'success')
    return redirect(url_for('topic_questions', topic_id=Question.query.get_or_404(question_id).topic_id))

@app.route('/approve_comment/<int:comment_id>', methods=['POST'])
def approve_comment(comment_id):
    if not current_user.role == 'teacher':
        flash('Only teachers can approve comments.', 'danger')
        return redirect(url_for('home'))
    
    comment = Comment.query.get_or_404(comment_id)
    comment.approved = True
    db.session.commit()
    flash('Comment approved.', 'success')
    return redirect(url_for('manage_comments'))  


@app.route('/manage_comments')
def manage_comments():
    if not current_user.is_authenticated:
        print("User is not authenticated")
        flash('You need to be logged in to access this page.', 'danger')
        return redirect(url_for('login'))

    if not current_user.role == 'teacher':
        print(f"User {current_user.username} is not a teacher")
        flash('You need to be a teacher to access this page.', 'danger')
        return redirect(url_for('home'))
    

    print(f"User {current_user.username} is a teacher and accessing manage_comments")
    comments = Comment.query.filter_by(approved=False).all()
    return render_template('manage_comments.html', comments=comments)

@app.route('/related_questions/<int:topic_id>', methods=['POST'])
def related_questions(topic_id):
    input_text = request.form.get('input_text', '')
    related_questions = find_related_questions(input_text, topic_id)

    # Convert the related questions to a list of dictionaries for JSON response
    results = [{'id': q.id, 'content': q.content} for q in related_questions]
    
    return jsonify(results)


@app.route('/topics/<int:topic_id>/answers/<int:answer_id>/delete', methods=['POST'])
def delete_answer(topic_id, answer_id):
    # Ensure the user is logged in and is a teacher
    if 'user_id' not in session or session['role'] != 'teacher':
        flash('You do not have permission to delete answers.', 'danger')
        return redirect(url_for('topic_questions', topic_id=topic_id))

    # Retrieve the answer and check if it exists
    answer = Answer.query.get_or_404(answer_id)
    
    # Delete the answer
    db.session.delete(answer)
    db.session.commit()

    flash('Answer deleted successfully!', 'success')
    return redirect(url_for('topic_questions', topic_id=topic_id))
