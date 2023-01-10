from flask import Flask, render_template, url_for, request, redirect, Blueprint, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
#database initilisation
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
#secret key
app.config['SECRET_KEY'] = 'secret'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login" 

@login_manager.user_loader
def load_user(user_id):
        return user.query.get(int(user_id))


#users schema
class user(db.Model, UserMixin):
     id = db.Column(db.Integer, primary_key=True)
     username  = db.Column(db.String(20), nullable=False, unique=True)
     password = db.Column(db.String(80), nullable=False)

#handle registrations
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), 
        Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = user.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


#handle logins
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), 
        Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
        InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

#tasks schema
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Integer, default=0)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    def __repr__(self):
        return '<Task %r>' % self.id


#dashboard/ tasks
@app.route('/', methods=['POST', 'GET'])
@login_required
def index():
    if request.method == "POST":
        task_content = request.form['content']
        new_task = Todo(content = task_content)
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect ('/')
        except:
            return "There was an issue adding your task"

    else:
        tasks = Todo.query.order_by(Todo.date_created).all()
        date = datetime.now().strftime("%A")
        print (date)
        return render_template('index.html', tasks=tasks, date=date)

#deleting tasks
@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect('/')
    except:
        return "Deleting didnt work sorry"

@app.route('/update/<int:id>', methods=['POST', 'GET'])
def update(id):
    task = Todo.query.get_or_404(id)
    if request.method == 'POST':
        task.content = request.form['content']
        try:
            db.session.commit()
            return redirect ('/')
        except:
            return "There was an issue updating tasks for today"
    else:
        return render_template('update.html', task=task )

#login page
@app.route('/login', methods=['POST', 'GET']) 
def login():
    form = LoginForm()
    if form.validate_on_submit():
        User = user.query.filter_by(username=form.username.data).first()
        if User:
            if bcrypt.check_password_hash(User.password, form.password.data):
                login_user(User)
                return redirect(url_for('index'))
    return render_template('login.html', form=form)
@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


#registration page
@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = user(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)
