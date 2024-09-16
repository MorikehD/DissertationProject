from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session
from flask_login import LoginManager, current_user
from flask_mail import Mail




app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///questions.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SESSION_TYPE'] = 'filesystem'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
Session(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Adjust as necessary
login_manager.init_app(app)
login_manager.login_message_category = 'info'

from app import routes, models


# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your email provider's SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'morikehd@gmail.com'  # Your email address
app.config['MAIL_PASSWORD'] = 'soft prrg jfwe pmbj'  # Your email password
app.config['MAIL_DEFAULT_SENDER'] = ('Remote Learning Questioning Tool', 'morikehd@gmail.com')
app.config['MAIL_SUPPRESS_SEND'] = False  # Ensure emails are actually sent
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)



