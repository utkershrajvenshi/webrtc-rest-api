from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, SubmitField
from wtforms.validators import email_validator, InputRequired

class SignUpForm(FlaskForm):
    email = EmailField('Email Address',validators=[InputRequired, email_validator])
    password = PasswordField('Password', validators=[InputRequired])
    submit = SubmitField('Submit')