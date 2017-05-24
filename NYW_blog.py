import os
import re
import random
import hashlib
import hmac
import datetime
import webapp2
import time
from string import letters

# import jinja2 library
import jinja2

# import google app engine data store library
from google.appengine.ext import db
from google.appengine.ext.db import metadata

# Store html files in the folder templates
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
# Using jinja2 to load templates. Eneable autoescape for HTML and XML. 
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = '!dwsg#@kjsdc&*vs&)~#'

def render_str(template, **params):
    """ Pass parameters into template """
    t = jinja_env.get_template(template)
    return t.render(params)

class BlogHandler(webapp2.RequestHandler):
    """ BlogHandler class for rendering template """

    def write(self, *a, **kw):
        """ Pass the non-keyworded and keyworded variable-length argument to the function  """
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ Gets the template and passes it with paramanters to a file level function called render_str """
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


    ##### Cookie security portion #####

    def set_secure_cookie(self, name, val):
        """ Set secure cookie """
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    
    def read_secure_cookie(self, name):
        """ Check secure cookie """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """ Set cookie to login user """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """ Reset cookie when user logout """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
  
    def initialize(self, *a, **kw):
        """ Initialize page and get user from cookie """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


##### User portion #####

def make_salt(length = 5):
    """ Create random salt """
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    """ Hash password with salt. If no salt, make one """
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    """ Validate password hash """
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def make_secure_val(val):
    """ Create a secure value """
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    """ Check a secure value """
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def users_key(group = 'default'):
    """ Define key for users group """
    return db.Key.from_path('users', group)

#####   User Login Decorator    #####
def login_required(func):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    def login(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if not self.user:
            self.redirect("/login")
        else:
            func(self, *args, **kwargs)
    return login

class User(db.Model):
    """ Database to store users data """
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


##### Blog portion #####

def blog_key(name = 'default'):
    """ Define key for blog """
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    """ Database to store user post data """
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    author_name = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.IntegerProperty(default = 0)

    def render(self):
        """ Insert line breaks in post content """
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p = self)

class Comment(db.Model):
    """ Database to store post comments """
    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)
    commentor = db.StringProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    #Retrieve total number of comments for post
    @classmethod
    def count_by_post_id(cls, post_id):
        c = Comment.all().filter('post =', post_id)
        return c.count()

    #Display all comments for a post
    @classmethod
    def all_by_post_id(cls, post_id):
        c = Comment.all().filter('post =', post_id).order('-created')
        return c

class Like(db.Model):
    """ Database to store post likes """
    post_id = db.IntegerProperty(required = True)
    user_id = db.IntegerProperty(required=True)


class Main(BlogHandler):
    """ Main Page Handler """
    def get(self):
        """ Redirect to login page """
        self.redirect('/login')

class BlogFront(BlogHandler):
    """ Blog Front Page Handler """
    @login_required
    def get(self):
        """ Retrieve all the last 20 blog posts """
        posts = db.GqlQuery("select * from Post order by created desc limit 20")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    """ Post Page Handler """
    @login_required
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            return self.error(404)
        #Retrieve comment information
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        if not post:
            return self.error(404)

        self.render("permalink.html", post=post,
                    comments_count=comments_count,
                    comments=comments)


class NewPost(BlogHandler):
    """ New Post Handler """
    @login_required
    def get(self):
        if self.user:

            self.render('newpost.html')
        else:
            self.redirect('/login')

    @login_required
    def post(self):
        if not self.user:
            self.redirect('/login')
            return

        user_id = self.user.key().id(),    
        author_name = self.user.name
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), 
                     user_id = self.user.key().id(),
                     author_name = self.user.name, 
                     subject = subject, 
                     content = content)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "Please input your subject and content !"
            self.render('newpost.html', subject=subject, content=content, error=error)


class Signup(BlogHandler):
    """ Signup Handler """    
    def get(self):
        self.render('signup-form.html')

    def post(self):
        # REGEX, regular expression and requirement for user signup
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        def valid_username(username):
            return username and USER_RE.match(username)

        PASS_RE = re.compile(r"^.{5,20}$")
        def valid_password(password):
            return password and PASS_RE.match(password) 

        EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        def valid_email(email):
            return not email or EMAIL_RE.match(email)

        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)
        # Validate username, password and email as per requirement
        if not valid_username(self.username):
            params['error_username'] = " Invalid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = " Invalid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = " Passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = " Invalid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        """ Check if user already exist """
        u = User.by_name(self.username)
        if u:
            msg = ' User already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')


class Login(BlogHandler):
    """ Login Handler """       
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        # Check if correct username and password
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/home')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)


class Logout(BlogHandler):
    """ Login Handler """  
    def get(self):
        self.logout()
        self.redirect('/login')


class Welcome(BlogHandler):
    """ Welcome Handler """  
    def get(self):
        """ Wecome note to new signup user """
        if self.user:
            self.render('welcome.html', author_name = self.user.name)
        else:
            self.redirect('/signup')


class EditPost(BlogHandler):
    """ Edit Post Handler """ 
    @login_required 
    def get(self, post_id):
        posts = db.GqlQuery("select * from Post order by created desc limit 20")
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post is not None:
                if post.user_id == self.user.key().id():
                    self.render("editpost.html", subject=post.subject, content=post.content)
                else:
                    error = "You do not have access to edit this post."
                    self.render("front.html", error=error)
            else:
                error = "This post does not exist."
                self.render('front.html', error=error)        
        else:
            self.redirect('/login')        

    @login_required 
    def post(self, post_id):          
        subject = self.request.get('subject')
        content = self.request.get('content')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.user_id == self.user.key().id():
                if subject and content:
                    key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                    post = db.get(key)
                    if post:
                        post.subject = subject
                        post.content = content
                        post.put()
                        self.redirect('/post/%s' % post_id)
                    else:
                        error = "This post does not exist."
                        self.render("front.html", author_name = self.user.name,
                        posts=posts, error=error)
                else:
                    error = "Please input your subject and content !"
                    self.render("editpost.html", subject=subject,
                                content=content, error=error)
            else:
                error = "You do not have access to edit this post."
                self.render("front.html", error=error) 
        else:
            self.redirect('/login')      


class DeletePost(BlogHandler):
    """ Delete Post Handler """  
    @login_required
    def get(self, post_id):
        posts = db.GqlQuery("select * from Post order by created desc limit 20")
        key = db.Key.from_path('Post', int(post_id) , parent=blog_key())
        post = db.get(key)

        if self.user:
            if post is not None:
                if post.user_id == self.user.key().id():
                    post.delete()
                    error = "Your post has been deleted."
                    self.render("deletepost.html", error=error, post=post)
                else:
                    error = "You do not have access to delete this post."
                    self.render("front.html", error=error)
            else:
                error = "This post does not exist."
                self.render("front.html", error=error)
        else:    
            self.redirect('/login') 


class NewComment(BlogHandler):
    """ New Comment handler """
    @login_required
    def post (self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        
        comment = self.request.get('comment')

        if comment:
            c = Comment(comment=comment, post=post_id,
                        user_id = self.user.key().id(),
                        commentor = self.user.name)
            c.put()
            # For GAE Database slow update
            time.sleep(0.1)
            self.redirect('/post/%s' % post_id)


class EditComment(BlogHandler):
    """ Edit Comment handler """
    @login_required
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        if comment:
            if comment and comment.user_id == self.user.key().id():
                self.render("editcomment.html", comment=comment.comment)
            else:
                error = "You can only edit your own comment."
                self.render("front.html", error=error)
        else:
            error = "This comment does not exist."
            self.render("front.html", error=error)


    @login_required
    def post(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            #Retrieve comment information
            comments = Comment.all_by_post_id(post_id)
            comments_count = Comment.count_by_post_id(post_id)

            if comment.user_id == self.user.key().id():
                comment_content = self.request.get("comment")
                if comment_content:
                    comment.comment = comment_content
                    comment.put()
                    # For GAE Database slow update
                    time.sleep(0.1)
                    self.redirect('/post/%s' % post_id)
                else:
                    error = "Please enter a comment."
                    self.render(
                        "editcomment.html",
                    comment=comment.comment, error=error)
        else:
            error = "This comment does not exist."
            self.render("front.html", error=error)


class DeleteComment(BlogHandler):
    """ Delete Comment handler """
    @login_required
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        if comment:
            if comment.user_id == self.user.key().id():
                comment.delete()
                error = "Your comment has been deleted."
                self.render("deletecomment.html", error=error)
            else:
                error = "You can only delete your own comment."
                self.render("front.html", error=error)
        else:
            error = "This comment does not exist."
            self.render("front.html", error=error)


class LikePost(BlogHandler):
    # """ Like handler """
    @login_required
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id) , parent=blog_key())
        post = db.get(key)

        user_id = self.user.key().id()    
        if post:
            if not post.user_id == self.user.key().id():
                like  = Like.all().filter(
                    'post_id =', int(post_id)).filter('user_id =', user_id)
                if(like.get()):
                    like[0].delete()
                    post.likes = post.likes - 1
                    post.put()
                    self.redirect('/post/%s' % post_id)
                else:
                    like = Like(post_id = int(post_id), user_id= user_id)
                    like.put()
                    post.likes = post.likes + 1
                    post.put()
                    self.redirect('/post/%s' % post_id)
            else:
                error = "You cannot like your own post."
                self.render("front.html", error = error)
        else:
            error = "This post does not exist."
            self.render("front.html", error=error)


##### To experience with ROT13 #####

class Rot13(BlogHandler):
    """ Rot13 Handler """  
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')
        self.render('rot13-form.html', text = rot13)


app = webapp2.WSGIApplication([('/', Main),
                               ('/home', BlogFront),
                               ('/post/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/post/editpost/([0-9]+)', EditPost),
                               ('/post/deletepost/([0-9]+)', DeletePost),  
                               ("/post/([0-9]+)/newcomment", NewComment),
                               ("/post/([0-9]+)/comment/([0-9]+)/edit", EditComment),
                               ("/post/([0-9]+)/comment/([0-9]+)/delete", DeleteComment),
                               ("/post/([0-9]+)/like", LikePost),
                               ('/rot13', Rot13),
                               ],
                              debug=True)

