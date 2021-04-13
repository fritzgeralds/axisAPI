from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

class RequiredIf(DataRequired):

    def __init__(self, other_field_name, *args, **kwargs):
        self.other_field_name = other_field_name
        super(RequiredIf, self).__init__(*args, **kwargs)

    def __call__(self, form, field):
        other_field = form._fields.get(self.other_field_name)
        if other_field is None:
            raise Exception('no field named "%s" in form' % self.other_field_name)
        if bool(other_field.data):
            super(RequiredIf, self).__call__(form, field)

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

class AddCompany(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()])
    site = StringField('Site', validators=[DataRequired()])
    nvr = StringField('NVR IP', validators=[DataRequired()])
    subnet = StringField('Subnet', validators=[DataRequired()])
    remote = BooleanField('Remote Access')
    remaddr = StringField('Remote Address', validators=[RequiredIf('remote')])
    submit = SubmitField('Add')