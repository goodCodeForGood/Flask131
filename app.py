from flask import Flask, render_template, flash, request, redirect, url_for
from forms import LoginForm, RegistrationForm
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators
from wtforms.validators import DataRequired, Length, EqualTo
from wtforms.widgets import TextArea
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin
from flask_login import login_user, logout_user, current_user, login_required
from datetime import datetime, timedelta
import time
import os

#create the object of Flask
app  = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config.update(
    SECRET_KEY='this-is-a-secret',
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS = False
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

@app.before_first_request
def create_tables():
    db.create_all()
    
#login code
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'Login'

##############################################
#     Creating Posting Functionality         #
##############################################
#Creating a Blog Post Model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

#Create a Post Form
class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()], widget=TextArea())
    author = StringField("Author", validators=[DataRequired()])
    submit = SubmitField("Submit")

# Add Post Page
@app.route('/add-post', methods =['GET', 'POST'])
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data)
        # Empty form
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        
        # Add post to DB
        db.session.add(post)
        db.session.commit()
        # Returns Message
        flash("Post Submitted Successfully!")
        
    # Redirect to the webpage
    return render_template("add_post.html", form=form)

##############################################
#    Creating Following Capability           #
##############################################

followers = db.Table('followers', 
                     db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
                     db.column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class User(UserMixin, db.Model):
    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin = (followers.c.follower_id == id),
        secondaryjoin = (followers.c.followed_id == id),
        backref = db.backref('followers', lazer = 'dynamic'), lazy = 'dynamic')
    
    
    
#This is our model
class UserInfo(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(100), unique = True)
    password = db.Column(db.String(100))



    def __init__(self, username, password):
        self.username = username
        self.password = password
##############################################

@login_manager.user_loader
def load_user(user_id):
    return UserInfo.query.get(int(user_id))




#creating our routes
@app.route('/')
@login_required
def index():

    name = current_user.username

    return render_template('index.html', name = name)



#login route
@app.route('/login' , methods = ['GET', 'POST'])
def Login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = UserInfo.query.filter_by(username=form.username.data).first()

            if user:
                if check_password_hash(user.password, form.password.data):
                    login_user(user)

                    return redirect(url_for('index'))


                flash("Invalid Credentials")

    return render_template('login.html', form = form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('Login'))



#register route
@app.route('/register' , methods = ['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method = 'sha256')
        username = form.username.data
        password = hashed_password


        new_register =UserInfo(username=username, password=password)

        db.session.add(new_register)

        db.session.commit()

        return redirect(url_for('Login'))


    return render_template('registration.html', form=form)


@app.route('/home')
def home():
    #getting posts from database
    posts = Posts.query.order_by(Posts.date_posted.desc()).all()
    return render_template('home.html', posts = posts)

#run flask app
if __name__ == "__main__":
    app.run(debug=True)