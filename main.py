#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import random
import hashlib
import hmac
from string import letters
import cgi
import time
import datetime

import webapp2
import jinja2

from google.appengine.ext import db

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
POST_RE = re.compile(r"^/blog/(\d+)")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, cookie_val):
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        return self.request.cookies.get(name)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('uid')
        self.user = uid and User.by_id(int(uid))



def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class User(db.Model):
   username = db.StringProperty(required = True)
   pw_hash = db.StringProperty(required = True)
   created = db.DateTimeProperty(auto_now_add = True)

   @classmethod
   def by_id(cls, uid):
        return User.get_by_id(uid)

class BlogPost(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add= True)
    username = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", blogpost= self)

class MainHandler(BlogHandler):
    def get(self):
        if self.user:
            username = self.request.cookies.get('username')
            redirect_url = '/users/' + username
            self.redirect(redirect_url)
        else:
            self.render('index.html')

class RegisterHandler(BlogHandler):
    def get(self):
        if self.user:
            username= self.read_cookie('username')
            redirect_url = '/users/' + username
            self.redirect(redirect_url)
        else:
            self.render('register.html')

    def post(self):
        username= self.request.get('username')
        password = self.request.get('password')
        verify= self.request.get('verify')

        username_error= self.validate_username(username)
        password_error = self.validate_password(password, verify)
        verify_error = self.validate_verify(verify, password)

        if (not username_error) and (not password_error) and (not verify_error):
            pw_hash = hashlib.md5(password).hexdigest()

            user = User(username=username, pw_hash=pw_hash)
            user.put()
            self.set_cookie('username', str(username))
            self.set_cookie('pw_hash', str(pw_hash))
            self.set_cookie('uid', str(user.key().id()))

            redirect_url = '/users/' + username
            self.redirect(redirect_url)
            #self.response.headers.add_header('Set-Cookie', 'username='+str(username) + '; Path=/')
            #self.response.headers.add_header('Set-Cookie', 'password='+str(password) + '; Path=/')
            #self.redirect('/')
        else:
            self.render('register.html', username_error=username_error, password_error=password_error, verify_error=verify_error)

    def validate_username(self,username):
        if USER_RE.match(username):
            user = db.GqlQuery("select * from User where username=:1", username).get()
            #users= User.all().filter('username =', username).get()
            if user:
                return "Sorry! This username already exists."
            else:
                return ""
        return "Username is not valid."

    def validate_password(self,password, verify):
        if PASSWORD_RE.match(password):
            return ""
        return "Password is not valid."

    def validate_verify(self,verify, password):
        if verify == password:
            return ""
        return "Passwords do not match."


class LoginHandler(BlogHandler):
    def get(self):
        if self.user:
            username= self.read_cookie('username')
            redirect_url = '/users/' + username
            self.redirect(redirect_url)
        else:
            self.render('login.html')

    def post(self):
        username= self.request.get('username')
        password = self.request.get('password')
        pw_hash = hashlib.md5(password).hexdigest()

        user = db.GqlQuery('select * from User where username=:1 and pw_hash=:2', username, pw_hash).get()

        if user:
            self.set_cookie('username', str(username))
            self.set_cookie('pw_hash', str(pw_hash))
            self.set_cookie('uid', str(user.key().id()))
            self.redirect('/users/%s'%username)
        else:
            self.render('login.html', error='Incorrect username or password')


class BlogPageHandler(BlogHandler):
    def get(self, username):
        #if self.user:
        #   self.render('blogtemplate.html', username=username)
        #else:
        #   self.redirect('/')
        check_username = self.request.cookies.get('username')
        if self.user and username != check_username :
            posts = db.GqlQuery('select * from BlogPost where username=:1 order by created desc limit 10', username)
            self.render('blogtemplate.html', posts=posts, username=username, check_username=check_username)
        elif not self.user:
            posts = db.GqlQuery('select * from BlogPost where username=:1 order by created desc limit 10', username)
            self.render('blogtemplate_unregistered.html', posts=posts, username=username)
        else:
            if username == check_username:
                posts = db.GqlQuery('select * from BlogPost where username=:1 order by created desc limit 10', username)
                self.render('blogtemplate_registered.html', posts=posts, username=username)


class NewPostHandler(BlogHandler):
    def get(self, username):
        check_username = self.request.cookies.get('username')
        if self.user and username == check_username:
            self.render('newpost.html', username=username)
        else:
            self.redirect('/')

    def post(self, username):
        check_username = self.request.cookies.get('username')
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            blogpost = BlogPost(username=username, subject=subject, content=content)
            blogpost.put()
            pid = blogpost.key().id()
            self.redirect('/users/%s/%s'%(username, str(pid)))          
        else:
            self.render('newpost.html', error="You need both a title and content!", subject=subject, content=content, username=username)

class PostHandler(BlogHandler):
    def get(self, username, pid):
        key = db.Key.from_path('BlogPost', int(pid))
        post = db.get(key)
        #self.write(post.content)
        post.content = post.content.replace('\n', '<br>')
        if self.user:
            check_username = self.request.cookies.get('username')
            self.render('post.html', post=post, check_username=check_username, username=username, pid=str(pid))
        else:
            self.render('post_unregistered.html', post=post)

class LogoutHandler(BlogHandler):
    def get(self):
        self.set_cookie('username', '')
        self.set_cookie('pw_hash', '')
        self.set_cookie('uid', '')
        referrer = self.request.headers.get('referer')
        if referrer:
            self.redirect(referrer)
        else:
            self.redirect('/')
 
class ContactHandler(BlogHandler):
    def get(self):
        self.render('contact.html')

class AboutHandler(BlogHandler):
    def get(self):
        self.render('about.html')

class HelpHandler(BlogHandler):
    def get(self):
        self.render('help.html')  

class EditPostHandler(BlogHandler):
    def get(self, username, post_id):
        check_username = self.request.cookies.get('username')
        if self.user and username == check_username:
            key = db.Key.from_path('BlogPost', int(post_id))
            post = db.get(key)
            self.render('editpost.html', post=post, username=username)
        else:
            self.redirect('/')

    def post(self, username, post_id):
        check_username = self.request.cookies.get('username')
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content and username == check_username:
            key = db.Key.from_path('BlogPost', int(post_id))
            blogpost = db.get(key)
            blogpost.subject = subject
            blogpost.content = content
            blogpost.put()
            self.redirect('/users/%s/%s'%(username, str(post_id)))          
        else:
            self.render('editpost.html', error="You need both a title and content!", subject=subject, content=content, username=username)

class DeletePostHandler(BlogHandler):
    def get(self, username, post_id):
        check_username = self.request.cookies.get('username')
        if self.user and username == check_username:
            key = db.Key.from_path('BlogPost', int(post_id))
            db.delete(key)
            time.sleep(1)
            self.redirect('/users/%s'%username)
        else:
            self.redirect('/users/%s/%s'%(username, post_id))    

class ArchiveHandler(BlogHandler):
    def get(self, username):
        check_username= self.request.cookies.get('username')
        blogposts = db.GqlQuery('select * from BlogPost where username=:1 order by created desc', username)  
        time_now = datetime.datetime.now().strftime("%Y")     
        self.render('archive.html', user_self=self, blogposts=blogposts, username=username, time_now=time_now, check_username=check_username)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/register', RegisterHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/contact', ContactHandler),
    ('/about', AboutHandler),
    ('/help', HelpHandler),
    (r'^/users/([a-zA-Z0-9_-]{3,20}$)', BlogPageHandler),
    (r'/users/([a-zA-Z0-9_-]{3,20})/newpost', NewPostHandler),
    (r'/users/([a-zA-Z0-9_-]{3,20})/archive', ArchiveHandler),
    (r'/users/([a-zA-Z0-9_-]{3,20})/(\d+)', PostHandler),
    (r'/users/([a-zA-Z0-9_-]{3,20})/(\d+)/edit', EditPostHandler),
    (r'/users/([a-zA-Z0-9_-]{3,20})/(\d+)/delete', DeletePostHandler),
], debug=True)
