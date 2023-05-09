import smtplib
from functools import wraps
from wtforms.validators import DataRequired
from flask import Flask, render_template, request, redirect, url_for, flash, g, abort
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, SubmitField
from flask_bootstrap import Bootstrap4
from flask_ckeditor import CKEditor, CKEditorField
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship


# db = SQLAlchemy()
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blojek.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# db.init_app(app)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
WTF_CSRF_SECRET_KEY = '8BYkEfBA6O6donzWlSihBXox7C0sKR6basdsdf'
app.secret_key = b'8BYkEfBA6O6donzWlSihBXox7C0sKR6basdsddxasdf'
bootstrap = Bootstrap4(app)
csrf = CSRFProtect(app)
ckeditor = CKEditor(app)


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    print(user_id)
    return db.session.query(User).get(user_id)


class Blog(db.Model):
    __tablename__ = 'blog_post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True, nullable=False)
    subtitle = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)
    author = db.Column(db.String, nullable=False)
    img_url = db.Column(db.String, nullable=False)
    children = relationship("Comments")


class Comments(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'), nullable=False)
    comment = db.Column(db.String, nullable=False)
    users = relationship("User", back_populates="children")


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    children = relationship("Comments",  back_populates="users")


with app.app_context():
    db.create_all()


class PostForm(FlaskForm):
    title = StringField('Title')
    subtitle = StringField('Subtitle')
    body = CKEditorField('Body')
    author = StringField('Author')
    img_url = StringField('img_url')
    submit = SubmitField('Save post')


class CommentForm(FlaskForm):
    comment = CKEditorField('My comment:')
    submit = SubmitField('Post my comment')


class RegisterForm(FlaskForm):
    name = StringField('Your name:')
    email = StringField('Your e-mail:')
    password = StringField('Password')
    submit = SubmitField('Register')


class LogonForm(FlaskForm):
    email = StringField('Your e-mail:')
    password = StringField('Password')
    submit = SubmitField('Log in')


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() != '1':
            return abort(404)
            # return render_template('404.html'), 404
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def home():
    data = db.session.query(Blog).all()
    return render_template("index.html", posts=data, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('You are already have an account, please log in with your e-mail!')
            return render_template("login.html")
        password_salted = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        newuser = User(
            email=request.form.get('email'),
            password=password_salted,
            name=request.form.get('name'),
        )
        db.session.add(newuser)
        db.session.commit()
        return redirect(url_for('home'))
    form = RegisterForm()
    return render_template("register.html", form=form, newone=True)


@app.route('/logon', methods=['POST', 'GET'])
def logon():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        print(email, password)
        user = User.query.filter_by(email=email).first()
        if user:
            print(user)
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            flash('Your password doesnt match!')
            return redirect(url_for('logon'))
        flash('Your email doesnt exist!')
        return redirect(url_for('logon'))
    form = LogonForm()
    return render_template("register.html", form=form, newone=False)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/contact', methods=["POST", "GET"])
def contact():
    if request.method == "GET":
        return render_template("contact.html", sented="false", logged_in=current_user.is_authenticated)

    username = request.form['username']
    email = request.form['email']
    phone = request.form['phone']
    message = request.form['message']

    my_email = "severeff@gmail.com"
    to_email = "egorii@list.ru"
    password = "qgbucfjtkecefapc"

    with smtplib.SMTP("smtp.gmail.com") as connection:
        connection.starttls()
        connection.login(user=my_email, password=password)
        connection.sendmail(
            from_addr=my_email,
            to_addrs=to_email,
            msg=f"Subject:New message from site\n\nName: {username}\nE-mail: {email}\nPhone: {phone}\nText: {message}"
        )
    return render_template("contact.html", sented="true", logged_in=current_user.is_authenticated)


@app.route('/about')
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:num>", methods=["POST", "GET"])
@admin_only
def edit_post(num):
    if request.method == "POST":
        post_to_edit = db.get_or_404(Blog, num)
        post_to_edit.title = request.form['title']
        post_to_edit.subtitle = request.form['subtitle']
        post_to_edit.body = request.form['body']
        post_to_edit.author = request.form['author']
        post_to_edit.img_url = request.form['img_url']
        db.session.commit()
        return redirect(url_for("post", num=num))
    post_ed = db.session.query(Blog).get(num)
    edit_form = PostForm(
        # id=post_ed.id,
        title=post_ed.title,
        subtitle=post_ed.subtitle,
        img_url=post_ed.img_url,
        author=post_ed.author,
        body=post_ed.body
    )
    return render_template("new_post.html", form=edit_form, num=num, newone=False,
                           logged_in=current_user.is_authenticated)


@app.route("/post/<int:num>")
def post(num):
    data = db.session.query(Blog).get(num)
    data_comment = Comments.query.filter_by(post_id=num).all()
    comm_form = CommentForm()
    return render_template("post.html", post=data, comments=data_comment, comm_form=comm_form,
                           logged_in=current_user.is_authenticated)


@app.route("/add-comment/<int:num>", methods=["POST", "GET"])
def add_comment(num):
    if request.method == "POST":
        newcomm = Comments(
            user_id=current_user.get_id(),
            post_id=num,
            comment=request.form['comment'],
        )
        db.session.add(newcomm)
        db.session.commit()
        return redirect(url_for("post", num=num))


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def new_post():
    if request.method == "POST":
        newpost = Blog(
            title=request.form['title'],
            subtitle=request.form['subtitle'],
            body=request.form['body'],
            author=request.form['author'],
            img_url=request.form['img_url'],
        )
        db.session.add(newpost)
        db.session.commit()
        return redirect(url_for("home"))
    form = PostForm()
    return render_template("new_post.html", form=form, newone=True, logged_in=current_user.is_authenticated)

# @app.route("/send_me")
# def send_me():
#     return render_template("send_me.html")

# @app.route("/form_entry", methods=["POST"])
# def receive_data():
#     username = request.form['username']
#     print(username)
#     email = request.form['email']
#     print(email)
#     phone = request.form['phone']
#     print(phone)
#     message = request.form['message']
#     print(message)
#     return render_template("success.html")


if __name__ == "__main__":
    app.run(debug=True)
