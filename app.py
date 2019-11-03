from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_wtf import FlaskForm, form
from wtforms import Form, StringField, TextAreaField, validators, StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
# from flask_login import LoginManager, logout_user  #this is for flask-login
# from app import login   # this is for flask-login
from werkzeug.security import generate_password_hash, check_password_hash
import os
import subprocess
from hashlib import sha256 as SHA256
from secrets import token_hex
from datetime import datetime

app = Flask(__name__)
Bootstrap(app)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = 'bd0c7d441f27d441f27567d441f2b6176a'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#  DB Setup stuff
def setup_db():
    db.drop_all()
    db.create_all()
    # add default users
    # add tester (non-admin account)
    uname = 'tester'
    pword = 'testpass'
    hasher = SHA256()
    # Add password to hash algorithm.
    hasher.update(pword.encode('utf-8'))
    # Generate random salt.
    salt = token_hex(nbytes=16)
    # Add random salt to hash algorithm.
    hasher.update(salt.encode('utf-8'))
    # Get the hex of the hash.
    pword_store = hasher.hexdigest()
    # Add a two factor auth number
    twofa = '5555555555'
    # Is an admin? 0 is no; 1 is yes
    isadmin = 0
    # Store the new user in the database.
    new_user = User(uname=uname, pword=pword_store, salt=salt, twofa=twofa, isadmin=isadmin)
    db.session.add(new_user)
    # Probably want error handling, etc. For this simplified code,
    # we're assuming all is well.
    db.session.commit()
    # add tester (non-admin account)
    uname = 'admin'
    pword = 'Administrator@1'
    hasher = SHA256()
    # Add password to hash algorithm.
    hasher.update(pword.encode('utf-8'))
    # Generate random salt.
    salt = token_hex(nbytes=16)
    # Add random salt to hash algorithm.
    hasher.update(salt.encode('utf-8'))
    # Get the hex of the hash.
    pword_store = hasher.hexdigest()
    # Add a two factor auth number
    twofa = '12345678901'
    # Is an admin? 0 is no; 1 is yes
    isadmin = 1
    # Store the new user in the database.
    new_user = User(uname=uname, pword=pword_store, salt=salt, twofa=twofa, isadmin=isadmin)
    db.session.add(new_user)
    # Probably want error handling, etc. For this simplified code,
    # we're assuming all is well.
    db.session.commit()

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uname = db.Column(db.String(25), nullable=False, unique=True)
    pword = db.Column(db.String(64), nullable=False)
    salt = db.Column(db.String(16), nullable=False)
    twofa = db.Column(db.String(15), nullable=False)
    isadmin = db.Column(db.Integer, nullable=False, default=0)
    checks = db.relationship('SpellCheck', backref='check_records', lazy=True)
    user_session = db.relationship('LoginRecord', backref='session_records', lazy=True)

    def __repr__(self):
        return f"User('{self.user_id}', '{self.uname}', '{self.pword}', '{self.salt})', '{self.twofa}')"


class LoginRecord(db.Model):
    __tablename__ = 'login_records'
    record_number = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    time_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    time_off = db.Column(db.DateTime)
    user = db.relationship(User)

    def __repr__(self):
        return f"login_record('{self.record_number}', '{self.userid}', '{self.time_on}', '{self.time_off}')"


class SpellCheck(db.Model):
    __tablename__ = 'spellcheck_records'
    record_number = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    input_checked = db.Column(db.Text, nullable=False)
    results = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return f"SpellCheck('{self.record_number}', '{self.userid}', '{self.input_checked}', '{self.results}')"

# forms used in templates
class LoginForm(FlaskForm):
    uname = StringField('uname', validators=[DataRequired()])
    pword = PasswordField('pword', validators=[DataRequired()])
    two_fa_field = StringField('2fa', id="2fa", validators=[DataRequired()])
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    uname = StringField(id='uname', validators=[DataRequired(), Length(min=2, max=20)])
    pword = PasswordField(id='pword', validators=[DataRequired()])
    #    confirm_password = PasswordField('confirm pword', validators=[DataRequired(), EqualTo('password')])
    two_fa_field = StringField('2fa', id="2fa", validators=[DataRequired()])
    submit = SubmitField('Register me')


class SpellCheckForm(FlaskForm):
    inputtext = TextAreaField('inputtext', render_kw={"rows": 15, "cols": 45})
    submit = SubmitField("Check Spelling")


userdict = {'tester': {'password': 'testpass', '2fa': '5555555555'}}

result = ''
success = ''


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    global userdict
    if login_form.validate_on_submit():
        queryforuser = User.query.filter_by(uname=login_form.uname.data).all()
        if len(queryforuser) == 1:
            pword = login_form.pword.data
            hasher = SHA256()
            # Add password to hash algorithm.
            hasher.update(pword.encode('utf-8'))
            # Generate random salt.
            salt = queryforuser[0].salt
            # Add random salt to hash algorithm.
            hasher.update(salt.encode('utf-8'))
            # Get the hex of the hash.
            pword_store = hasher.hexdigest()
            # use this to see what's being compared - flash(f"{queryforuser[0].pword}, {pword_store}")
            if queryforuser[0].pword == pword_store:
                if queryforuser[0].twofa == login_form.two_fa_field.data:
                    flash("Login successful for user {}".format(login_form.uname.data), 'success')
                    session['uname'] = login_form.uname.data  # create session cookie
                    # create a log record  (login record)
                    new_login = LoginRecord(user_id=login_form.uname.data)
                    db.session.add(new_login)
                    db.session.commit()
                    return render_template('login.html', form=login_form, result='success')
                else:
                    flash("Login unsuccessful.  bad 2fa")
                    return render_template('login.html', form=login_form, result='Two-factor failure')
            else:
                flash("Login unsuccessful, bad password")
                return render_template('login.html', form=login_form, result='incorrect')
        else:
            flash("You are not registered user, please register")
            return render_template('login.html', form=login_form, result='incorrect')
    return render_template('login.html', form=login_form,)


@app.route('/register', methods=['GET', 'POST'])
def register():
    register_form = RegistrationForm()
    if register_form.validate_on_submit():
        queryforuser = User.query.filter_by(uname=register_form.uname.data).all()
        # flash(f"your query resulted in {queryforuser}")
        if len(queryforuser) == 0:
            uname = register_form.uname.data
            pword = register_form.pword.data
            hasher = SHA256()
            # Add password to hash algorithm.
            hasher.update(pword.encode('utf-8'))
            # Generate random salt.
            salt = token_hex(nbytes=16)
            # Add random salt to hash algorithm.
            hasher.update(salt.encode('utf-8'))
            # Get the hex of the hash.
            pword_store = hasher.hexdigest()
            # Add a two factor auth number
            twofa = register_form.two_fa_field.data
            # Is an admin? 0 is no; 1 is yes
            isadmin = 0
            # Store the new user in the database.
            new_user = User(uname=uname, pword=pword_store, salt=salt, twofa=twofa, isadmin=isadmin)
            db.session.add(new_user)
            # Probably want error handling, etc. For this simplified code, we're assuming all is well.
            db.session.commit()
            flash(f"Registration successful for user {register_form.uname.data} Please login")
            return render_template('register.html', form=register_form, success='success')
        else:
            flash(f"User {register_form.uname.data} already registered")
            return render_template('register.html', form=register_form, success='failure')
    return render_template('register.html', form=register_form)


@app.route('/spell_check', methods=['GET', 'POST'])
def spell_check():
    if 'uname' in session:
        spell_check_form = SpellCheckForm()
        if spell_check_form.validate_on_submit():
            input_text = spell_check_form.inputtext.data  # put text from form into a field
            input_file = open("input_file.txt", 'w')  # open file
            input_file.write(str(input_text))  # put text into file
            input_file.close()  # close the file
            # call subprocess
            misspelled = subprocess.run(['./a.out', './input_file.txt', './wordlist.txt'],
                                        stdout=subprocess.PIPE).stdout.decode('utf-8').replace("\n", ", ").rstrip(
                ", ")
            # spell_check_form.misspelled_stuff.data = misspelled_words
            # log the event
            new_query = SpellCheck(user_id='uname', input_checked=input_text,results=misspelled)
            db.session.add(new_query)
            db.session.commit()
            return render_template('spell_check.html', form=spell_check_form, misspelled=misspelled)
        return render_template('spell_check.html', form=spell_check_form)
    else:
        flash("You are not logged in, Please log in")
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    updateloginrec = LoginRecord.query.filter_by(user_id='uname').all()
    flash(f"{updateloginrec}")
    # updateloginrec[0].time_off = datetime.utcnow()
    # db.session.commit()
    session.pop('username', None)
    return redirect(url_for('login'))


# @app.route('/history')
# def history():
# publish history total number of queries in an element with id=numqueries.   presented in an element with
# id=query# where # is a unique identifier for that query. The user can click on any given query
# and enter a query review page, described in the next subsection.


# @app.route('login_history')
# def login_history():
# admins should be able to access the login history of a given user
# page should contain a form with id=userid that an admin can fill in to get the login history of a given user
# history should be returned in a list: id=login#  id=login#_time   id=logout#_time
# user is still logged in logout is 'N/A'


# @app.route("/history/query#")
# def query():

setup_db()
if __name__ == '__main__':
    app.run(debug=True)
