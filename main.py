from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import secrets

# CREATE AND INITIATE FLASK OBJECT
app = Flask(__name__)

secret = secrets.token_hex(16)
app.config['SECRET_KEY'] = secret
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CREATE THE FLASK LOGIN MANAGER OBJECT AND INITIALIZE
login_manager = LoginManager()
login_manager.init_app(app)


# CREATE TABLE IN DB (Mixins are just like inheriting classes in OOP. They add functionality to your pre-existing class)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# Line below only required once, when creating DB.
# db.create_all()


@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':  # USE THIS WHEN YOU ARE NOT USING WTFORMS. WITH WTFORMS, IF FORM.VALIDATE_ON_SUBMIT():
        with app.app_context():
            if User.query.filter_by(email=request.form.get('email')).first():
                flash('Email already exists! Login instead', 'error')
                # time.sleep(3)
                return render_template('login.html')
            else:
                # ENCRYPTING AND SALTING PASSWORD BEFORE SAVING TO DATABASE
                encrypted_password = generate_password_hash(
                    password=request.form.get('password'),
                    method='pbkdf2:sha256',  # Add pbkdf2:sha256:200000 to increase the computational complexity
                    salt_length=8
                )

                new_user = User(email=request.form.get('email'),  # THIS AS WELL. INSTEAD OF form.email.data
                                password=encrypted_password,
                                name=request.form.get('name')
                                )
                db.session.add(new_user)
                db.session.commit()
                # session['name'] = request.form.get('name')  # Stores a variable for use here in the backend temps.
                # Not needed. I found another way. But know it just incase (you'll need to import it from flask)

                # Log in the user after the register and adding details to database
                login_user(new_user)

                return redirect(url_for('secrets'))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Find the email in the database
        with app.app_context():
            user = User.query.filter_by(email=email).first()

            # Check stored password hash against entered password hash
            if check_password_hash(user.password, password=password):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash('Invalid username or password. Please try again!', 'error')

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=True)  # Current_user.name is a method from flask_login


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
