from flask_mail import Message
import logging


def send_notification_email(recipient, subject, body):
    from app import mail
    msg = Message(subject, recipients=[recipient])
    msg.body = body
    mail.send(msg)
  