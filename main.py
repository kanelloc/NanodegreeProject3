import os
import webapp2
import jinja2
import hmac
import hashlib
import random
import re
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'tfu.uy~Iutsd.p0233asdsad,hgGasddd^Y&ff'


# Cookies section
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Password hashing salting section
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Handler(webapp2.RequestHandler):
    """docstring for Handler"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def read_Secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.header.add_header(
            'Set-Cookie',
            'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_Secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))


# Class Post is for the dataset to store posts
# Class User is for the dataset to store users


class Post(db.Model):
    """docstring for Posts"""
    subject = db.StringProperty(required=True)
    blog_post = db.TextProperty(required=True)
    created_at = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()


class MainPage(Handler):
    """docstring for MainPage"""
    def get(self):
        #check if loged in
        if self.user:
            username = self.user.username
        else:
            username = ''
        self.render('main.html', username=username)

# Front page to show all the posts


class BlogFront(Handler):
    """Query the posts and returns them all for BlogFront"""
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created_at DESC ")
        self.render('front.html', posts=posts)


class PostPage(Handler):
    """PostPage for each post based on id"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=None)
        post = db.get(key)

        if post:
            post_id = post.key().id()
            self.render('permalink.html', post=post, post_id=post_id)
        else:
            self.error(404)


class NewPost(Handler):
    """new post created by NewPost"""
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/blog/signup")

    def post(self):
        subject = self.request.get("subject")
        blog_post = self.request.get("blog_post")

        error = dict(error_subject="", error_blog_post="")
        has_error = False
        # Check for errors in the submit post page
        if not subject:
            error['error_subject'] = "You sould enter a subject!"
            has_error = True

        if not blog_post:
            error['error_blog_post'] = "You sould enter a blog post!"
            has_error = True

        if has_error:
            self.render("newpost.html", subject=subject,
                        blog_post=blog_post, has_error=has_error, **error)
        else:
            p = Post(subject=subject, blog_post=blog_post)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))


# Signup/Signin/Signout section
class SignUp(Handler):
    """signup Handler"""
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        # Query to search the dataset for the given username.
        checkuser = User.all()
        checkuser.filter('username =', username)
        result = checkuser.get()
        if result:
            params['error_username'] = "THe username is already in use"
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            pw_hash = make_pw_hash(username, password)
            u = User(username=username, pw_hash=pw_hash, email=email)
            u.put()
            success = "You have successfuly register to the blog"
            self.render('main.html', success=success)


class SignIn(Handler):
    """docstring for SignIn"""
    def get(self):
        self.render('signin.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        u = User.all().filter('username = ', username).get()
        if u and valid_pw(username, password, u.pw_hash):
            self.login(u)
            self.render('main.html')
        else:
            self.write('den uparxei o xristis')


class Unit3Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.username)
        else:
            self.redirect('/blog/signup')
# Routes


app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/?', BlogFront),
                               ('/blog/signup', SignUp),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/blog/signin', SignIn)], debug=True)
