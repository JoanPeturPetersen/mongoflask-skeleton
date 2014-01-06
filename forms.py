
from flask_wtf import Form, RecaptchaField
from wtforms import TextField
from wtforms import HiddenField
from wtforms.validators import DataRequired


class LoginForm(Form):
    username = TextField('username', validators=[DataRequired()])
    password = TextField('password', validators=[DataRequired()])


class RECAPTCHA_Form(Form):
    username = HiddenField('username', validators=[DataRequired()])
    password = HiddenField('password', validators=[DataRequired()])
    recaptcha = RecaptchaField()

