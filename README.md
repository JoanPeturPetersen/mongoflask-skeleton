mongoflask-skeleton
===================

A code skeleton for starting a flask web page with login/sessions using MongodDB as database for the users.

Still work in progress, does not work fully yet...

Requirements
------------
Flask, a MongoDB server, and PyMongo. The code runs on Python 2.7, maybe other vesions too.

Features
--------
* Limits number of login tries with a defined duration, as to prevent automatic password guessing.
* Supports multiple secrets, so that one user might log in from several devices at once.
* Long session secrets stored on server side to prevent session stealing by guessing session secret/key.

Missing features
----------------
The skeleton does not handle bruteforce, dictionary, or similar login attacks well.
Only as simple preliminary prevention has been implemented: A username is only allowed to try to log in at a maximum rate.
It is a problem that it is only based upon the username, as someone who knows a username, could lock that user out of the system, by continously trying to log in.
A smarter system has to be implemented.

Secure redirects.
