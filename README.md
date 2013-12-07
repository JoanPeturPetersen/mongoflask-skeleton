mongoflask-skeleton
===================

A code skeleton for starting a flask web page with login/sessions using mondodb as database.

Still work in progress, does not work yet...

Requirements
------------
Flask, a MongoDB server, and PyMongo. The code runs on Python 2.7, maybe other vesions too.


Features
--------

Missing features
----------------
The skeleton does not handle bruteforce, dictionary, or similar login attacks well.
Only as simple preliminary prevention has been implemented: A username is only allowed to try to log in at a maximum rate.
It is a problem that it is only based upon the username, as someone who knows a username, could lock that user out of the system, by continously trying to log in.
A smarter system has to be implemented.

