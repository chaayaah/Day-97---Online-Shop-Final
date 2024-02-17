from flask import render_template, session, request, redirect, url_for, flash
from flask_login import login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

import os

from shop import app, db
from .forms import RegistrationForm, LoginForm
from .models import User
from shop.products.models import Addproduct, Category, Brand


@app.route('/admin')
def admin():
    if 'email' not in session:
        flash("please login first.", 'danger')
        return redirect(url_for('login'))
    products = Addproduct.query.all()
    return render_template('admin/index.html',
                           title='Admin page',
                           products=products)

@app.route('/brands')
def brands():
    if 'email' not in session:
        flash("please login first.", 'danger')
        return redirect(url_for('login'))
    brands = Brand.query.order_by(Brand.id.desc()).all()
    return render_template('admin/brand.html', title='brands',brands=brands)


@app.route('/categories')
def categories():
    if 'email' not in session:
        flash("please login first.", 'danger')
        return redirect(url_for('login'))
    categories = Category.query.order_by(Category.id.desc()).all()
    return render_template('admin/brand.html', title='categories',categories=categories)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == "POST" and form.validate():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data,
            password=hash_and_salted_password
        )
        db.session.add(user)
        flash(f"{form.name.data}, Thank you for registering.")
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('admin/register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate():
        user = User.query.filter_by(email = form.email.data).first()
        if not user:
            flash("This email does not exist. Please try again.", 'danger')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, form.password.data):
            flash("Password incorrect. Please try again.")
            return redirect(url_for('login'))
        else:
            session['email'] = form.email.data
            flash(f'welcome {form.email.data} you are logged-in now','success')
            return redirect(url_for('admin'))
    return render_template('admin/login.html', form=form)