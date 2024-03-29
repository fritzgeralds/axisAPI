from app import app, db
from flask import render_template, flash, redirect, url_for, request, jsonify
from app.forms import LoginForm, ScanForm, AddCompany
from flask_login import current_user, login_user, logout_user, login_required
from app.models import User, Camera, Company, Site
from app.func import camera_scan, camera_info
from werkzeug.urls import url_parse

@app.route('/')
@app.route('/index')
@login_required
def index():
    customers = Company.query.order_by(Company.name)
    sites = Site.query.order_by(Site.name)
    cameras = Camera.query.order_by(Camera.id)
    return render_template('index.html', title='AXIS Config Tool', cameras=cameras, customers=customers, sites=sites)

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

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    form = ScanForm()
    cameras = []
    if form.validate_on_submit():
        subnet = form.subnet1.data + '.' + form.subnet2.data + '.' + form.subnet3.data + '.' + form.subnet4.data
        cameras = camera_scan(subnet)
    return render_template('scan.html', title='Scan - AXIS Config Tool', form=form, cameras=cameras)

@app.route('/new_scan', methods=['GET', 'POST'])
@login_required
def scanner():
    oct1 = request.args.get('oct1')
    oct2 = request.args.get('oct2')
    oct3 = request.args.get('oct3')
    subnet = f'{oct1}.{oct2}.{oct3}.0'
    for i in camera_scan(subnet):
        cam = i
        camera = [cam[0],cam[1],cam[2],cam[3]]
        print(camera)


@app.route('/add', methods=['GET', 'POST'])
def test():
    form = AddCompany()
    if form.validate_on_submit():
        comp = Company.query.filter_by(name=form.name.data).first()
        if comp is None:
            newcomp = Company(name=form.name.data)
            db.session.add(newcomp)
            db.session.commit()
        newsite = Site(name=form.site.data, company=form.name.data, nvr=form.nvr.data,
                       subnet=form.subnet.data, remote=form.remote.data, remaddr=form.remaddr.data)
        db.session.add(newsite)
        db.session.commit()
        flash('Company Added Successfully!')
        return redirect(url_for('index'))
    return render_template('add.html', form=form)

@app.route('/remove')
def remove():
    r = ':'.join(request.args.get('q')[i:i + 2] for i in range(0, len(request.args.get('q')), 2))
    cam = Camera.query.filter_by(mac=r).first()
    db.session.delete(cam)
    db.session.commit()
    return "Nothing"

@app.route('/assign')
def assign():
    r = ':'.join(request.args.get('q')[i:i + 2] for i in range(0, len(request.args.get('q')), 2))
    s = request.args.get('site')
    print(r)
    print(s)
    cam = Camera.query.filter_by(mac=r).first()
    cam.site = s
    db.session.commit()
    cam = Camera.query.filter_by(mac=r).first()
    cam.company = Site.query.filter_by(name=s).first().company
    db.session.commit()
    return "Nothing"

@app.route('/info/<ip>')
@login_required
def info(ip):
    cam = Camera.query.filter_by(ip=ip).first_or_404()
    conf = camera_info(ip)
    conf['site'] = cam.site
    print(conf)
    update = str(conf['update'])
    print(update)
    return render_template('info.html', cam=cam, conf=conf, update=update)

@app.route('/get_sites/<customer>')
def get_sites(customer):
    company = Company.query.filter_by(name=customer).first().sites
    sites = []
    for site in company:
        sites.append(site.name)
    print(jsonify(sites))
    return jsonify(sites)