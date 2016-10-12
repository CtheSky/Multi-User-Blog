import os
import hmac

import webapp2
import jinja2
from google.appengine.ext import db

from validate import *
from model import *
from hash import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinjia_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                                autoescape=True)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params["user"] = self.user
        t = jinjia_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            "Set-Cookie",
            "%s=%s; Path=/" % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie("user_id", str(user.key().id()))

    def logout(self):
        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie("user_id")
        self.user = uid and User.by_id(int(uid))

    def with_no_user(self):
        self.initialize(self.request, self.response)
        return not self.user

    def user_match_post_author(self, pid):
        self.initialize(self.request, self.response)
        user = self.user
        post = Post.by_id(long(pid))
        return user and user.key().id() == post.uid

    def user_match_comment_author(self, cid):
        self.initialize(self.request, self.response)
        user = self.user
        comment = Comment.by_id(long(cid))
        return user and user.key().id() == comment.uid


class MainPage(Handler):
    def get(self):
        self.initialize(self.request, self.response)
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        self.render("post_main.html", posts=posts)


class NewPost(Handler):
    def get(self):
        self.initialize(self.request, self.response)
        if not self.user:
            signin_error = "You have to sign in first."
            self.render("post_main.html", signin_error=signin_error)
        else:
            self.render("new_post.html")

    def post(self):
        if self.with_no_user():
            self.redirect("/")
            return

        uid = self.user.key().id()
        title = self.request.get("title")
        subtitle = self.request.get("subtitle", "")
        content = self.request.get("content")

        if title and content:
            content = content.replace('\n', '<br>')
            post = Post(uid=uid, title=title, subtitle=subtitle, content=content)
            post.put()
            self.redirect("/post/" + str(post.key().id()))
        else:
            error = "Both title, subtitle and content are needed!"
            self.render("new_post.html", title=title, content=content, error=error)


class EditPost(Handler):
    def get(self, pid):
        if not self.user_match_post_author(pid):
            self.redirect("/")
            return

        post = Post.by_id(long(pid))
        title = post.title
        subtitle = post.subtitle
        content = post.content

        self.render("edit_post.html", title=title, subtitle=subtitle, content=content)

    def post(self, pid):
        if not self.user_match_post_author(pid):
            self.redirect("/")
            return

        post = Post.get_by_id(long(pid))
        post.subtitle = self.request.get("subtitle", "")
        post.content = self.request.get("content")
        post.put()
        self.redirect("/post/" + str(post.key().id()))


class DeletePost(Handler):
    def post(self, pid):
        if not self.user_match_post_author(pid):
            self.redirect("/")
            return

        post = Post.by_id(long(pid))
        post.delete()

        self.redirect("/my_post")


class ViewPost(Handler):
    def get(self, pid):
        pid = long(pid)

        post = Post.by_id(pid)
        author = User.by_id(post.uid)
        comments = Comment.by_pid(pid)

        like = None
        if not self.with_no_user():
            like = Like.by_uid_and_pid(self.user.key().id(), pid)

        if post:
            self.render("post.html", post=post, author=author, comments=comments, like=like)
        else:
            self.error(404)


class MyPost(Handler):
    def get(self):
        if self.with_no_user():
            self.redirect("/")
            return

        uid = self.user.key().id()
        posts = Post.by_uid(uid)
        self.render("my_post.html", posts=posts)


class LikePost(Handler):
    def post(self):
        pid = self.request.get("pid")
        if self.with_no_user() or self.user_match_post_author(pid):
            self.redirect("/")
            return

        pid = long(pid)
        post = Post.by_id(pid)
        post.liked += 1
        post.put()

        pid = long(pid)
        like = Like(uid=self.user.key().id(), pid=pid)
        like.put()

        self.redirect("/post/%s" % pid)


class NewComment(Handler):
    def post(self):
        if self.with_no_user():
            self.redirect("/")
            return

        uid = self.user.key().id()
        uname = self.user.name
        pid = long(self.request.get("pid"))
        content = self.request.get("content")

        if content:
            comment = Comment(uid=uid, uname=uname, pid=pid, content=content)
            comment.put()

        self.redirect("/post/%s" % pid)


class DeleteComment(Handler):
    def post(self):
        cid = self.request.get("cid")
        if not self.user_match_comment_author(cid):
            self.redirect("/")
            return

        cid = long(cid)
        pid = long(self.request.get("pid"))
        comment = Comment.by_id(cid)
        comment.delete()

        self.redirect("/post/%s" % pid)


class EditComment(Handler):
    def post(self):
        cid = self.request.get("cid")
        if not self.user_match_comment_author(cid):
            self.redirect("/")
            return

        cid = long(cid)
        pid = long(self.request.get("pid"))
        content = self.request.get("content")
        comment = Comment.by_id(cid)
        comment.content = content
        comment.put()

        self.redirect("/post/%s" % pid)


class SignUp(Handler):
    def post(self):
        have_error = False
        signup_error = None
        name = self.request.get('username')
        pw = self.request.get('password')
        verify = self.request.get('verify')

        if not valid_password(pw):
            have_error = True
            signup_error = "That wasn't a valid password."
        elif pw != verify:
            have_error = True
            signup_error = "Your passwords didn't match."

        # check duplicate username
        previous_user = User.by_name(name)
        if previous_user:
            have_error = True
            signup_error = "This name has been used, try another one."

        if not valid_username(name):
            have_error = True
            signup_error = "That's not a valid username."

        if have_error:
            self.render("post_main.html", username=name, signup_error=signup_error)
        else:
            user = User.register(name, pw)
            user.put()
            self.redirect("/")


class SignIn(Handler):
    def post(self):
        name = self.request.get('username_si')
        pw = self.request.get('password_si')

        u = User.login(name, pw)
        if u:
            self.login(u)
            self.redirect("/")
        else:
            signin_error = "Invalid username or password."
            self.render("post_main.html", username_si=name, signin_error=signin_error)


class LogOut(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/new_post', NewPost),
    ('/my_post', MyPost),
    ('/post/(\d+)', ViewPost),
    ('/like_post', LikePost),
    ('/edit_post/(\d+)', EditPost),
    ('/delete_post/(\d+)', DeletePost),
    ('/new_comment', NewComment),
    ('/delete_comment', DeleteComment),
    ('/signup', SignUp),
    ('/signin', SignIn),
    ('/logout', LogOut)
], debug=True)
