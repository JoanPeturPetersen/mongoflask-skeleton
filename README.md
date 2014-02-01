mongoflask-skeleton
===================

NOTE: Not secure at the moment - working on the admin interface.

There are notes in the code on what to secure before deployment. For example remember to change the `admin` password. At some point a list of points will be made.

A code skeleton for starting a flask web page with login/sessions using MongodDB as database for the users.

Still work in progress, does not work fully yet...

Requirements
------------
Flask, a MongoDB server, and PyMongo. The code runs on Python 2.7, maybe other vesions too.

Trying it out
-------------
* Start a local MongoDB server
* Create some data by running `python db_demo_populate.py GO`
* Start the web server `python login_skeleton.py`
* Go to `127.0.0.1:5000/` in our browser
* Try to log in as `Stan` with password `123`.

Features
--------
* Limits number of login tries with a defined duration, as to prevent automatic password guessing.
* Supports multiple secrets, so that one user might log in from several devices at once.
* Long session secrets stored on server side to prevent session stealing by guessing session secret/key.
* Secure redirect back to page requiring login.

Missing features
----------------
The skeleton does handle bruteforce, dictionary, or similar login attacks to some extent.
As a preliminary countermeasure a username is only allowed to try to log in at a maximum rate. If this 
rate is exceeded, then the user cap be asked to answer a reCAPTCHA question (if enabled). The CAPTCHA
was introduced, so that a bruteforce attack should not be able to lock out a user. This can happen if
we only allow a user to try a certain rate of paswords.

Secure redirects.
