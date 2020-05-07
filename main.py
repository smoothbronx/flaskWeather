# importing libraries
import requests
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import hashlib


# Configuring the application
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///weather.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = hashlib.sha3_512('smoothbronx69'.encode()).hexdigest()
db = SQLAlchemy(app)
manager = LoginManager(app)


# Models and connecting to the database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    ip = db.Column(db.String(50), nullable=False)
    creation_datetime = db.Column(db.String(50), nullable=False)


class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    userid = db.Column(nullable=False)


# Function for getting the request results
def get_weather_data(city):
    url = f'http://api.openweathermap.org/data/2.5/weather?q={ city }&units=metric&appid=271d1234d3f497eed5b1d80a07b3fcd1'
    r = requests.get(url).json()
    return r


# Processing the main page: output the response to the request
@app.route('/')
@login_required
def index_get():
    cities = City.query.filter_by(userid=current_user.id)
    weather_data = []
    for city in cities:
        r = get_weather_data(city.name)

        weather = {
            'city': city.name,
            'temperature': r['main']['temp'],
            'description': r['weather'][0]['description'],
            'icon': r['weather'][0]['icon'],
        }
        weather_data.append(weather)
    return render_template('index.html', weather_data=weather_data)

# Processing the main page: User input
@app.route('/', methods=['POST'])
def index_post():
    err_msg = ''
    new_city = request.form.get('city')
    if new_city:
        existing_city = City.query.filter_by(userid=current_user.id, name=new_city).first()
        if not existing_city:
            new_city_data = get_weather_data(new_city)
            if new_city_data['cod'] == 200:
                new_city_obj = City(name=new_city, userid=current_user.id)

                db.session.add(new_city_obj)
                db.session.commit()
            else:
                err_msg = 'City does not exist in the world!'
        else:
            err_msg = 'City already exists in the database!'

    if err_msg:
        flash(err_msg, 'error')
    else:
        flash('City added succesfully!')
    return redirect(url_for('index_get'))


# Processing of page deleting of the city
@app.route('/delete/<name>')
def delete_city(name):
    city = City.query.filter_by(userid=current_user.id, name=name).first()
    db.session.delete(city)
    db.session.commit()

    flash(f'Successfully deleted { city.name }', 'success')
    return redirect(url_for('index_get'))


# Getting an individual user ID
@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Processing the login page
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = User.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')
        else:
            flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')
    return render_template('login.html')


# Processing the register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')
    user_ip = request.remote_addr
    cr_datetime = datetime.now().strftime('%H:%M %m/%d/%Y')
    if request.method == 'POST':
        if not (login or password or password2):
            flash('Please, fill all fields!')
        elif password != password2:
            flash('Passwords are not equal!')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = User(login=login, password=hash_pwd, ip=user_ip, creation_datetime=cr_datetime)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login_page'))
    return render_template('register.html')


# Processing the logout page
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))


# Redirection function to the login page if the user's session has not started
@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)
    return response


# Application launch
if __name__ == '__main__':
    app.run('localhost', 8080)