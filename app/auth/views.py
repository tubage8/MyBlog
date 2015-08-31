from flask import render_template, redirect, request, url_for, flash
from flask.ext.login import login_user, logout_user, login_required, current_user
from . import auth
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, VerifyEmailForm, ResetPasswordForm
from app.models import User
from app import db
from ..email import send_email

@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()
        send_email(user.email, 'Confirm Your Account', 'auth/email/confirm', user=user, token=token)
        ###test###
        print '###register_test###' + url_for('auth.confirm', token=token, _external=True)
        ###test###
        flash('A confirmation email has been sent to you by email.')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)

@auth.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
    if current_user.is_authenticated() \
        and not current_user.confirmed \
        and request.endpoint[:5] != 'auth.'\
        and request.endpoint != 'static':
        return redirect((url_for('auth.unconfirmed')))

@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous() or current_user.confirmed:
        return  redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html', user=current_user)

@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user.email, 'Confirm Your Account',
                'auth/email/confirm', user=current_user, token=token)
    ###test###
    print '###confirm_test###' + url_for('auth.confirm', token=token, _external=True)
    ###test###
    flash('A new confirmation email has been sent to you by email')
    return redirect(url_for('main.index'))

@auth.route('/changepassword', methods=['GET', 'POST'])
@login_required
def changepassword():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_user.password = form.newpassword.data
        db.session.add(current_user)
        flash('Change password successfully!')
        return redirect(url_for('main.index'))
    return render_template('auth/changepassword.html', form=form)

@auth.route('/reset_password', methods=['GET', 'POST'])
def verify_email():
    form = VerifyEmailForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        token = user.generate_confirmation_token()
        send_email(form.email.data, 'Reset Your Password',
                   'auth/email/reset_password', user=user, token=token)
        ###test###
        print '###reset_password_test###' + url_for('auth.reset_password', token_email=token+'&'+user.email, _external=True)
        ###test###
        flash('A resetting-password email has been sent to you by email')
    return render_template('auth/verify_email.html', form=form)

@auth.route('/reset_password/<token_email>', methods=['GET', 'POST'])
def reset_password(token_email):
    form = ResetPasswordForm()
    [token, email] = token_email.split('&')
    user = User.query.filter_by(email=email).first()
    if form.validate_on_submit():
        if user is None or  not user.confirm(token):
            flash('Reset password wrong, please reset!')
            return redirect(url_for('auth.verify_email'))
        user.password = form.newpassword.data
        db.session.add(user)
        flash('Reset password successfully! Now you can login.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', user=user, form=form)

# @auth.route('/change_email', methods=['GET', 'POST'])
# @login_required
# def change_email():
