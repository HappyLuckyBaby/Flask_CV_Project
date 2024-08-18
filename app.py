# from flask import Flask, render_template, url_for, redirect
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import UserMixin
# from flask_wtf import FlaskForm, login_user, LoginManager, login_required, logout_user, current_user
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import InputRequired, Length, ValidationError
# from flask_bcrypt import Bcrypt

from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecreatkey'

# Initialize the SQLAlchemy object properly
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "Login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):  # Corrected name to RegisterForm
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})  # Corrected placeholder

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})  # Corrected placeholder

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one.")  # Corrected typo in username


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Username"})  # Corrected typo in validators
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Password"})
    
    submit = SubmitField("Login")  # Corrected Submit to submit for consistency

@app.route("/")
@app.route("/home")
def home():
    return render_template("home.html")


@app.route("/login", methods=['GET', 'POST'])
def Login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template("login.html", form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('Login'))

@app.route("/register", methods=['GET', 'POST'])
def Register():
    form = RegisterForm()  # Corrected form creation to RegisterForm

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username = form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('Login'))
    return render_template("register.html", form=form)


if __name__ == "__main__":
    app.run(debug=True, port=8080)


















# from flask import Flask, render_template, url_for
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import UserMixin
# from flask_wtf import FlaskForm
# from wtforms import SearchField, PasswordField, SubmitField
# from wtforms.validators import InputRequired, Length, ValidationError

# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
# app.config['SECRET_KEY'] = 'thisisasecreatkey'

# # Initialize the SQLAlchemy object properly
# db = SQLAlchemy(app)

# class User(db.Model, UserMixin):
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(20), nullable=False, unique=True)
#     password = db.Column(db.String(80), nullable=False)

# class RegisterFrom(FlaskForm):
#     username = StringField(Validators=[InputRequired(), Length(
#         min = 4, max = 20)], render_kw={"placeholder": "Password"})
    
#     passwrod = PasswordField(validators=[InputRequired(), Length(
#         min = 4, max = 20)], render_kw={"plaecHolder": "Password"})
    
#     submit = SubmitField("Register")

#     def validate_username(self, username):
#         existing_user_username = User.query.filter_by(
#             username=username.data).first()
        
#         if existing_user_username:
#             raise ValidationError(
#                 "That usernaem already exists. Please choose a different one.")

# class LoginForm(FlaskForm):
#     username = StringField(validatros=[InputRequired(),Length(
#         min = 4, maz = 20)], render_kw={"placeholder": "Username"})
    
#     password = PasswordField(validators=[InputRequired(), Length(
#         min = 4, max = 20)], render_kw={"placeholder": "Password"})
    
#     Submit = SubmitField("Login ")

# @app.route("/")
# @app.route("/home")
# def home():
#     return render_template("home.html")

# @app.route("/login", methods=['GET', 'POST'])
# def Login():
#     form = LoginForm()
#     return render_template("login.html", form=form)

# @app.route("/register", methods=['GET', 'POST'])
# def Register():
#     form = Register()
#     return render_template("register.html", form=form)

# if __name__ == "__main__":
#     app.run(debug=True, port=8080)

