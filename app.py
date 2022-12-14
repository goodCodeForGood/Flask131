#app.py
from flask import Flask, render_template, flash, redirect, url_for, request, session, g
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import InputRequired, ValidationError, DataRequired, EqualTo, Length, Email
from wtforms.widgets import TextArea
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from flask_bootstrap import Bootstrap
from datetime import datetime
import time
import os
import json
from time import time

#create the object of Flask
app  = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
Bootstrap(app)

app.config.update(
    SECRET_KEY='this-is-a-secret',
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    POSTS_PER_PAGE = 3
)

#login code
login_manager = LoginManager()
login_manager .init_app(app)
login_manager .login_view = 'Login'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

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

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<Message {}>'.format(self.body)

class MessageForm(FlaskForm):
    message = TextAreaField(('Message'), validators=[
        DataRequired(), Length(min=0, max=140)])
    submit = SubmitField(('Submit'))



##############################################
#    Creating Following Capability           #
##############################################

followers = db.Table(
    'followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('user.id'))
)

#This is our new model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    messages_sent = db.relationship('Message',foreign_keys='Message.sender_id',backref='author', lazy='dynamic')
    messages_received = db.relationship('Message',foreign_keys='Message.recipient_id',backref='recipient', lazy='dynamic')
    last_message_read_time = db.Column(db.DateTime)

    notifications = db.relationship('Notification', backref='user', lazy='dynamic')

    def __repr__(self):
        return '<user>'.format(self.username)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def followed_posts(self):
        followed = Post.query.join(
            followers, (followers.c.followed_id == Post.user_id)).filter(
                followers.c.follower_id == self.id)
        own = Post.query.filter_by(user_id=self.id)
        return followed.union(own).order_by(Post.timestamp.desc())

    def new_messages(self):
        last_read_time = self.last_message_read_time or datetime(1900, 1, 1)
        return Message.query.filter_by(recipient=self).filter(
            Message.timestamp > last_read_time).count()

    def add_notification(self, name, data):
        self.notifications.filter_by(name=name).delete()
        n = Notification(name=name, payload_json=json.dumps(data), user=self)
        db.session.add(n)
        return n


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.Float, index=True, default=time)
    payload_json = db.Column(db.Text)

    def get_data(self):
        return json.loads(str(self.payload_json))

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        g.search_form = SearchForm()
    g.locale = 'en'

@app.before_request
def make_session_permanent():
    session.permanent = True

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

    # posts = current_user.followed_posts()
    posts = Post.query.order_by(Post.timestamp.desc());
    page = request.args.get('page', 1, type=int)

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

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

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

@app.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get('page', 1, type=int)
    posts = current_user.followed_posts().all()

    return render_template('user.html', user=user, posts=posts, username=username)

@app.context_processor #to pass stuff to nav bar (via base.html)
def base():
     form = SearchForm()
     return dict(form=form)

@app.context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'Post': Post, 'Message': Message,
            'Notification': Notification}

@app.route('/search', methods=['POST'])
@login_required
def search():
    form = SearchForm()
    if form.validate_on_submit():
        post_searched = form.searched.data 
        user = User.query.filter_by(username=post_searched).first_or_404()

        return render_template('search.html', form=form, 
        searched=post_searched, user=user)

@app.route('/send_message/<recipient>', methods=['GET', 'POST'])
@login_required
def send_message(recipient):
    user = User.query.filter_by(username=recipient).first_or_404()
    form = MessageForm()
    if form.validate_on_submit():
        msg = Message(author=current_user, recipient=user,
                      body=form.message.data)
        db.session.add(msg)
        db.session.commit()
        flash(_('Your message has been sent.'))

        #Notification to update when user receives new pvt message 
        user.add_notification('unread_message_count', user.new_messages())
        db.session.commit()

        return redirect(url_for('main.user', username=recipient))
    return render_template('send_message.html', title=('Send Message'),
                           form=form, recipient=recipient)

@app.route('/messages') #route to view messages
@login_required
def messages():
    current_user.last_message_read_time = datetime.utcnow()

    #"..when the user goes to the messages page, 
    #at which point the unread count goes back to zero"
    current_user.add_notification('unread_message_count', 0)

    db.session.commit()
    page = request.args.get('page', 1, type=int)
    messages = current_user.messages_received.order_by(
        Message.timestamp.desc()).paginate(
            page=page, per_page=app.config['POSTS_PER_PAGE'],
            error_out=False)
    #new_messages = current_user.new_messages()
    session['new_messages'] = current_user.new_messages()
    db.session.add(messages)
    db.session.commit()

    next_url = url_for('messages', page=messages.next_num) \
        if messages.has_next else None
    prev_url = url_for('messages', page=messages.prev_num) \
        if messages.has_prev else None
    return render_template('messages.html', messages=messages.items,
                           next_url=next_url, prev_url=prev_url)

@app.route('/notifications')
@login_required
def notifications():
    since = request.args.get('since', 0.0, type=float)
    notifications = current_user.notifications.filter(
        Notification.timestamp > since).order_by(Notification.timestamp.asc())
    return jsonify([{
        'name': n.name,
        'data': n.get_data(),
        'timestamp': n.timestamp
    } for n in notifications])

@app.errorhandler(404)
def page_not_found(error):
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
