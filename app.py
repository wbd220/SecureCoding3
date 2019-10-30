from flask import Flask, render_template, request, url_for, redirect, flash, session
from flask_wtf import FlaskForm, form
from wtforms import Form, StringField, TextAreaField, validators, StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_bootstrap import Bootstrap
# from flask_login import LoginManager, logout_user  #this is for flask-login
# from app import login   # this is for flask-login
from werkzeug.security import generate_password_hash, check_password_hash
import os
import subprocess

app = Flask(__name__)
Bootstrap(app)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = 'bd0c7d441f27d441f27567d441f2b6176a'


# login = LoginManager(app)    # this is for flask-login


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
        if login_form.uname.data in userdict:
            if userdict[login_form.uname.data]['password'] == login_form.pword.data:
                if userdict[login_form.uname.data]['2fa'] == login_form.two_fa_field.data:
                    flash("Login successful for user {}".format(login_form.uname.data), 'success')
                    session['uname'] = login_form.uname.data  # create session cookie
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
        if register_form.uname.data not in userdict:
            userdict[register_form.uname.data] = {'password': register_form.pword.data,
                                                     '2fa': register_form.two_fa_field.data}
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
            return render_template('spell_check.html', form=spell_check_form, misspelled=misspelled)
        return render_template('spell_check.html', form=spell_check_form)
    else:
        flash("You are not logged in, Please log in")
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('login'))


# @app.route('/logout')   #  for flask-login
# def logout():
#     logout_user()
#     return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)