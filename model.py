from google.appengine.ext import db

from hash import *


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter("name =", name).get()
        return u

    @classmethod
    def register(cls, name, pw):
        pw_hash = make_pw_hash(name, pw)
        return User(name=name, pw_hash=pw_hash)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw_hash(name, pw, u.pw_hash):
            return u


class Post(db.Model):
    uid = db.IntegerProperty(required=True)
    uname = db.StringProperty(required=True)
    title = db.StringProperty(required=True)
    subtitle = db.StringProperty()
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    edited = db.DateTimeProperty(auto_now=True)
    liked = db.IntegerProperty(default=0)

    @classmethod
    def by_uid(cls, uid):
        # Use keys_only query to avoid Eventual Consistency
        return Post.get(Post.all(keys_only=True).filter("uid =", uid))

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid)


class Comment(db.Model):
    uid = db.IntegerProperty(required=True)
    uname = db.StringProperty(required=True)
    pid = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    edited = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, cid):
        return Comment.get_by_id(cid)

    @classmethod
    def by_pid(cls, pid):
        # Use keys_only query to avoid Eventual Consistency
        return Comment.get(Comment.all(keys_only=True).filter("pid =", pid))


class Like(db.Model):
    uid = db.IntegerProperty(required=True)
    pid = db.IntegerProperty(required=True)

    @classmethod
    def by_uid_and_pid(cls, uid, pid):
        # Use keys_only query to avoid Eventual Consistency
        return Like.get(Like.all(keys_only=True).filter("uid =", uid).filter("pid =", pid))
