from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User
from flask.ext.login import current_user

class LoginForm(Form):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me Logged in')
    submit = SubmitField('Log In')

class RegistrationForm(Form):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    username = StringField('Username', validators=[Required(), Length(1,64), Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

class ChangePasswordForm(Form):
    oldpassword = PasswordField('Old Password',validators=[Required(), Length(1,64)])
    newpassword = PasswordField('New Password', validators=[Required(), Length(1,64), EqualTo('newpassword2', message='Passwords must match')])
    newpassword2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Change')

    def validate_oldpassword(self, field):
        if not current_user.verify_password(field.data):
            raise ValidationError('Wrong Password')

class VerifyEmailForm(Form):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    submit = SubmitField('Verify Email')

    def validate_email(self, field):
        if not User.query.filter_by(email=field.data).first():
            raise ValidationError('This email has not been registered, please rigister!')

class ResetPasswordForm(Form):
    newpassword = PasswordField('New Password', validators=[Required(), Length(1,64), EqualTo('newpassword2', message='Passwords must match')])
    newpassword2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Reset')