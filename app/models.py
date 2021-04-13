from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Camera(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    make = db.Column(db.String(64))
    model = db.Column(db.String(128))
    ip = db.Column(db.String(15), index=True)
    mac = db.Column(db.String(17), unique=True)

    def __repr__(self):
        return '<Camera {}>'.format(self.mac)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), index=True, unique=True)
    sites = db.relationship('Site', backref='comp', lazy='dynamic')
    pass

class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(255), db.ForeignKey('company.name'))
    name = db.Column(db.String(255), index=True, unique=True)
    nvr = db.Column(db.String(15), index=True)
    subnet = db.Column(db.String(15), index=True)
    remote = db.Column(db.Boolean)
    remaddr = db.Column(db.String(255))
    pass

@login.user_loader
def load_user(id):
    return User.query.get(int(id))