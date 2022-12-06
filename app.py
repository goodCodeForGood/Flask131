from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, validators
from wtforms.validators import DataRequired, Length, EqualTo
from wtforms.widgets import TextArea
from flask_migrate import Migrate
from datetime import datetime, timedelta
import time

migrate = Migrate(app, db)

##############################################
#     Creating Posting Functionality         #
##############################################

# Creating the Blog Post Model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    
# Create Post Form
class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()], widget=TextArea)
    author = StringField("Author", validators=[DataRequired()])
    submit = SubmitField("Submit")
    
# Add a Post Page
@app.route('/add-post', methods=['GET', 'POST'])
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Posts(title = form.title.data, content=form.content.data, author=form.author.data)
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        db.session.add(post)
        db.session.commit()
        flash("Blog Post Submitted Successfully!")
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
    