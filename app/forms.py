from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ScanForm(FlaskForm):
    subnet1 = StringField('Subnet', validators=[DataRequired()])
    subnet2 = StringField(validators=[DataRequired()])
    subnet3 = StringField(validators=[DataRequired()])
    subnet4 = StringField(validators=[DataRequired()])
    submit = SubmitField('Scan')