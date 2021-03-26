from app import app
from flask import render_template, flash, redirect, url_for, request
from app.forms import LoginForm
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User
from werkzeug.urls import url_parse

@app.route('/')
@app.route('/index')
@login_required
def index():
    user = {'username':'root'}
    cameras = [
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:94',
            'ip': '172.16.1.72'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:9B',
            'ip': '172.16.1.77'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:87:F4',
            'ip': '172.16.1.90'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:5C',
            'ip': '172.16.1.94'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:99',
            'ip': '172.16.1.99'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:7B',
            'ip': '172.16.1.113'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:8E',
            'ip': '172.16.1.116'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:8A',
            'ip': '172.16.1.118'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:89:D7',
            'ip': '172.16.1.119'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:89:FB',
            'ip': '172.16.1.126'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:88:AF',
            'ip': '172.16.1.154'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE Mk II',
            'mac': 'AC:CC:8E:A9:5B:CB',
            'ip': '172.16.1.167'
        },
        {
            'make': 'AXIS',
            'model': 'M2026-LE',
            'mac': 'AC:CC:8E:75:89:E4',
            'ip': '172.16.1.193'
        },
        {
            'make': 'AXIS',
            'model': 'M3047-P',
            'mac': 'AC:CC:8E:B5:47:74',
            'ip': '172.16.1.83'
        },
        {
            'make': 'AXIS',
            'model': 'C3003-E',
            'mac': 'AC:CC:8E:F3:1A:F0',
            'ip': '172.16.1.92'
        },
        {
            'make': 'AXIS',
            'model': 'A8004-VE',
            'mac': 'AC:CC:8E:87:4B:6D',
            'ip': '172.16.1.96'
        },
        {
            'make': 'AXIS',
            'model': 'M3058',
            'mac': 'AC:CC:8E:DB:29:EC',
            'ip': '172.16.1.98'
        },
        {
            'make': 'AXIS',
            'model': 'A1001',
            'mac': 'AC:CC:8E:A9:B2:F1',
            'ip': '172.16.1.106'
        },
        {
            'make': 'AXIS',
            'model': 'M3047-P',
            'mac': 'AC:CC:8E:B5:47:61',
            'ip': '172.16.1.129'
        },
        {
            'make': 'AXIS',
            'model': 'P3224-LV Mk II',
            'mac': 'AC:CC:8E:67:D4:88',
            'ip': '172.16.1.136'
        },
        {
            'make': 'AXIS',
            'model': 'P3224-LV Mk II',
            'mac': 'AC:CC:8E:67:D4:91',
            'ip': '172.16.1.147'
        },
        {
            'make': 'AXIS',
            'model': 'P3224-LV Mk II',
            'mac': 'AC:CC:8E:67:D4:59',
            'ip': '172.16.1.190'
        }
    ]
    return render_template('index.html', title='AXIS Config Tool', cameras=cameras)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In - AXIS Config Tool', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', title='Settings - AXIS Config Tool')
