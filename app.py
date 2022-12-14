#app.py
from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, ValidationError, DataRequired, EqualTo, Length, Email
from wtforms.widgets import TextArea
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from datetime import datetime
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

#login code
login_manager = LoginManager()
login_manager .init_app(app)
login_manager .login_view = 'Login'

db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()

##############################################
#     Creating Posting Functionality         #
##############################################
#Creating a Blog Post Model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default = datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<post>'.format(self.body)

class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    post = TextAreaField('Say something', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

class SearchForm(FlaskForm):
    searched = StringField("Searched", validators=[DataRequired()])
    submit = SubmitField('Submit')

class SearchedMessageForm(FlaskForm):
    searchedMessage = StringField("SearchedMessage", validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.context_processor
def base1():
    form = SearchedMessageForm()
    return dict(form=form)

#search post/message by its title
@app.route('/searchedMessage', methods=['POST'])
@login_required
def searchedMessage():
    form = SearchedMessageForm()
    post = Post.query
    if form.validate_on_submit():
        post_searchedMessage = form.searchedMessage.data
        #post = Post.query.filter_by(title=post_searchedMessage).first_or_404()
        post = post.filter(Post.body.like('%' + post_searchedMessage + '%'))
        post = post.order_by(Post.title).all()

        return render_template('searchedMessage.html', form=form,
        searchedMessage=post_searchedMessage, user=user, post=post)

##############################################
#    Creating Following Capability           #
##############################################
followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

class EmptyForm(FlaskForm):
    submit = SubmitField('Submit')

#This is our new model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    followed = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    # def __init__(self, username, password):
    #     self.username = username
    #     self.password = password

    def __repr__(self):
        return '<user>'.format(self.username)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(
            followers.c.followed_id == user.id).count() > 0

    def followed_posts(self):
        followed = Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)).filter(
                followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

# Old model
# class UserInfo(UserMixin, db.Model):
#     id = db.Column(db.Integer, primary_key = True)
#     username = db.Column(db.String(100), unique = True)
#     password = db.Column(db.String(100))
#
#
#
#     def __init__(self, username, password):
#         self.username = username
#         self.password = password



@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

#'/' or index route
@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():

    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, body=form.post.data, author=current_user)

        form.title.data = ''
        form.post.data = ''

        db.session.add(post)
        db.session.commit()


        flash('Your message is now posted!')
        return redirect(url_for('index'))

    #To see followed posts only
    posts = current_user.followed_posts()

    #To see all posts whether followed or not
    # posts = Post.query.order_by(Post.timestamp.desc());

    return render_template('index.html', title='Home', form=form, posts=posts)


# Add Post Page
@app.route('/add-post', methods =['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, body=form.post.data, author=current_user)
        # Empty form
        form.title.data = ''
        form.post.data = ''
        # form.author.data = ''

        # Add post to DB
        db.session.add(post)
        db.session.commit()
        # Returns Message
        flash("Post Submitted Successfully!")

    # Redirect to the webpage
    return render_template("add_post.html", form=form)

# Login page route
@app.route('/login', methods=['GET', 'POST'])
def Login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()

            if user is None or not user.check_password(form.password.data):
                flash('Invalid Login Credentials')
                return redirect(url_for('Login'))
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form = form)

# Logout page route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

# Logout register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method = 'sha256')
        username = form.username.data
        password = hashed_password


        new_register =User(username=username, password=password)

        db.session.add(new_register)

        db.session.commit()

        return redirect(url_for('Login'))


    return render_template('registration.html', form=form)

#Delete user route
@app.route('/delete/<username>')
@login_required
def delete(username):
    if(username == current_user.username):
        delete_user = User.query.first_or_404(username)

        try:
            db.session.delete(delete_user)
            db.session.commit()
            flash('Success, User has been deleted!')
            logout_user()
            return redirect(url_for('index'))
        except:
            flash('Error, could not delete user')
    else:
        flash('You can not delete that user')
        return redirect(url_for('user', username=current_user.username))

#Follower user route
@app.route('/follow/<username>', methods=['POST'])
@login_required
def follow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot follow yourself!')
            return redirect(url_for('user', username=username))
        current_user.follow(user)
        db.session.commit()
        flash('You are following {}!'.format(username))
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))

#Unfollow user route
@app.route('/unfollow/<username>', methods=['POST'])
@login_required
def unfollow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash('User {} not found.'.format(username))
            return redirect(url_for('index'))
        if user == current_user:
            flash('You cannot unfollow yourself!')
            return redirect(url_for('user', username=username))
        current_user.unfollow(user)
        db.session.commit()
        flash('You are not following {}.'.format(username))
        return redirect(url_for('user', username=username))
    else:
        return redirect(url_for('index'))

#Open user profile route
@app.route('/user/<username>')
@login_required
def user(username):
    form = EmptyForm()
    user = User.query.filter_by(username=username).first_or_404()
    posts = current_user.followed_posts().all()

    return render_template('user.html', user=user, posts=posts, username=username, form=form)

@app.context_processor #to pass stuff to nav bar (via base.html)
def base():
     form = SearchForm()
     return dict(form=form)

#Search route
@app.route('/search', methods=['POST'])
@login_required
def search():
    form = SearchForm()
    if form.validate_on_submit():
        post_searched = form.searched.data
        user = User.query.filter_by(username=post_searched).first_or_404()

        return render_template('search.html', form=form,
        searched=post_searched, user=user)

#404 or error page route
@app.errorhandler(404)
def page_not_found(error):
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
