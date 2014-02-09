"""
Login/session skeleton for flask using mongodb as backend.

Remember that if you don't enable SSL (HTTPS), then all password will
be sent in plaintext.

Also remember to change 'app.secret_key' and reCAPTCHA settings if
used.

"""

from flask import Flask
from flask import request
from flask import render_template
from flask import redirect
from flask.ext.login import LoginManager, login_user, logout_user
from flask.ext.login import UserMixin, current_user, login_required
from pymongo import Connection
from pymongo.errors import DuplicateKeyError
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import random
import string
import datetime
from flask import flash, url_for
from urlparse import urljoin
from forms import LoginForm, RECAPTCHA_Form, RegisterForm
from forms import ForgotPasswordForm
from flask import session
from flask.ext.mail import Mail, Message
from copy import copy

# Application settings:
app = Flask(__name__)
app.secret_key = 'CHANGE ME'  # Set the secret key, it is also used by
                              # LoginManager.
app.debug = True              # Set False before deployment
DEBUG = True

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME='mongoflask@gmail.com',
    MAIL_PASSWORD='',
    MAIL_SENTFROM='mongoflask@gmail.com',)
mail = Mail(app)

# Login manager settings:
login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "/login"
login_manager.login_message = u"Please login."


# Database
con = Connection()
db = con.user_database
users = db.users

# Session config:
max_session_releases = 3  # Maximum number of valid secrets per user
max_secret_age_hours = 24.0  # Time for an secret to expire
max_password_guesses = 3  # Maximum number of password guesses within
                          # `password_window` minutes.
password_window = 15      #

# reCAPTCHA setting:
ENABLE_RECAPTCHA = True  # If true, then the user will be taken to a
  #  reCAPTCH page instead of being asked to wait when trying to login too
  #  often.
RECAPTCHA_PUBLIC_KEY = "6LeYIbsSAAAAACRPIllxA7wvXjIE411PfdB2gt2J"
    # required A public key.
RECAPTCHA_PRIVATE_KEY = "6LeYIbsSAAAAAJezaIq3Ft_hSTo0YtyeFG-JgRtu"
    # required A private key.


class User(UserMixin):

    """
    This class represents a user.

    This will be populated with data from the database.

    """

    def __init__(self, id):
        """`id` gives the public user id."""
        self.id = id
        self.name, self.secret = id.split("#")

    def is_active(self):
        """State of a user in the system."""
        return True


def check_password(user_doc, password):
    """Check if `password` is acceptable for user given in `user_doc`."""
    return check_password_hash(user_doc['saltedpw'], password)


def render(*args, **kwargs):
    """Render template with user data appended."""
    if 'user' in kwargs:
        raise Exception('Sorry, I already use this keyword for the ' +
                        'current user.')
    kwargs['user'] = current_user.__dict__
    return render_template(*args, **kwargs)


@login_manager.user_loader
def load_user(public_id):
    """
    Load user data from database.

    This function is required by the login manager plugin. This
    function is executed for each request that has a @login_required
    decorator to verify the user identity.

    """
    if DEBUG:
        print "Public ID: " + public_id
    split_pid = public_id.split("#")
    if not len(split_pid) == 2:
        return None  # Public id is not valid
    username, secret = split_pid
    user = users.find_one({u"username": username})
    if not 'secrets' in user:
        return None
    secrets = user['secrets']
    # Find the secret strings that have not expired:
    secret_strings = []
    for s in secrets:
        if s['created'] + datetime.timedelta(
                hours=max_secret_age_hours) > datetime.datetime.utcnow():
            secret_strings.append(s['value'])
    if secret in secret_strings:
        return User(public_id)
    else:
        return None  # Secret does not match


def generate_secret(length=32):
    """Return a secret consisting of letters and numbers."""
    return ''.join(random.choice(string.letters + string.digits)
                   for x in range(length))


def generate_public_userid(user_doc):
    """
    Generate an public ID for the user.
    
    Generate a public ID which is passed on to the client's browser.
    The ID also contains a secret, which is used to ensure that the ID
    is up to date. The secret should be updated when the user logs in,
    updates the password, or if the secret has expired.

    This method also updates the secret stored in the database.
    
    """
    delimiter = "#"
    username = user_doc['username']
    if delimiter in username:
        raise Exception("Username must not contain '%s'" % delimiter)
    # Update database with new secret and creation time:
    create_time = datetime.datetime.utcnow()
    secret = {'value': generate_secret(), 'created': create_time}
    public_id = username + "#" + secret['value']
    # Here we should update the user db entry with secret
    if 'secrets' in user_doc:
        secrets = user_doc['secrets']
    else:
        secrets = []
    secrets.append(secret)
    secrets = secrets[-max_session_releases:]
    users.update({u'username': username},
                 {"$set": {"secrets": secrets}})
    return public_id


def do_login_user(user_doc, password, skip_password=False):
    """
    Return true if user is successfully logged in.

    TODO: Check that user is activated.

    """
    if skip_password is False:
        if not check_password(user_doc, password):
            return False
    if 'active' in user_doc and not user_doc['active']:
        return False  # User not activated
    public_userid = generate_public_userid(user_doc)
    user = User(public_userid)
    if login_user(user):
        print "Logged in user: " + public_userid
        users.update({u'username': user_doc[u'username']},
                     {'$set': {'last-login': datetime.datetime.utcnow()}})
        return True
    else:
        print "Failed to login user: " + public_userid
        return False


def get_next_url():
    """Return the url to return to when user logs in."""
    next_url = url_for('index')
    target = session.pop('next', None)
    if target is not None:
        # Make sure it is on this server
        next_url = urljoin(request.host_url, target)
    session['next'] = request.args.get('next')
    return next_url


def _enough_time_passed(doc):
    try:
        last_attempts = doc['last_attempts']
    except KeyError:
        last_attempts = []
        users.update({u'username': doc[u'username']},
                     {'$set': {'last_attempts': last_attempts}})
    count_within_window = 0
    too_old = []
    for attempt in last_attempts:
        if attempt + datetime.timedelta(seconds=password_window * 60) \
                > datetime.datetime.utcnow():
                    count_within_window += 1
        else:
            too_old.append(attempt)  # Outside window
    # Don't store more than neccesary:
    sorted_attempts = sorted(last_attempts)
    too_old = list(set(sorted_attempts[:-max_password_guesses]) | set(too_old))
    # Remove old entries:
    if DEBUG:
        print "Removing old login attempts:", too_old
    if too_old:
        users.update({u'username': doc[u'username']},
                     {'$pullAll': {u'last_attempts': too_old}})
    return count_within_window + 1 <= max_password_guesses


def _add_login_attempt(user_doc):
    users.update({u'username': user_doc[u'username']},
                 {'$push': {'last_attempts': datetime.datetime.utcnow()}})


class UserAlreadyExists(Exception):

    """Thrown if the user already exists in the database."""

    pass


def add_user(data, activate=False):
    """Add a user to the user database.

    All data fields from the form are saved, so if you add a new field in
    the registration form it will be saved to the user record.
    The 'password' field is however salted.
    This methods only adds the user, if the username does not already exist.
    
    """
    data = copy(data)
    # Salt password:
    data['saltedpw'] = generate_password_hash(data['password'])
    del data['password']
    # Creation date for user:
    data['created'] = datetime.datetime.utcnow()
    # If not active, generate a activation secret:
    data['activation_secret'] = generate_secret()
    data['active'] = False
    try:
        users.insert(data, safe=True)
    except DuplicateKeyError:
        raise UserAlreadyExists('User already exists')
    return data


def send_registration_mail(data):
    """Sends an activation mail when a new user has registered."""
    msg = Message('Hello',
                  sender=app.config['MAIL_SENTFROM'],
                  recipients=[data['email']])
    # Data for the mail:
    activation = {'link': url_for('activate', username=data['username'],
                  activation_secret=data['activation_secret'],
                  _external=True)}
    msg.body = render('activation_email.txt', activation=activation)
    mail.send(msg)


# Routes ----------------------------------------------------------------


@app.route('/login/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Handle forgotten password form."""
    form = ForgotPasswordForm()
    return render('forgot_password.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_wtf():
    next_url = get_next_url()
    form = LoginForm()
    capform = RECAPTCHA_Form()
    is_cap = False
    if 'recaptcha_response_field' in request.form.keys():
        is_cap = True
        form = capform
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # We should clean userid first?
        user_doc = users.find_one({"username": username})
        if not user_doc is None:
            # Make sure enough time has passed:
            if not is_cap:
                if not _enough_time_passed(user_doc):
                    if ENABLE_RECAPTCHA:
                        capform = RECAPTCHA_Form()
                        capform.username.data = username
                        capform.password.data = password
                        return render('recaptcha.html', form=capform)
                    else:
                        flash('Please wait a while...')
                        return redirect(url_for('login'))
            _add_login_attempt(user_doc)
            if do_login_user(user_doc, password):
                return redirect(next_url)
            else:
                flash('Authentication failed A')
                return render('loginwtf.html', form=LoginForm())
                #return redirect(url_for('login_wtf',
                #    next=request.args.get('next')))
        else:
            # No user with that username
            flash('Authentication failed')
            return render('loginwtf.html', form=form)
    else:
        if is_cap:
            return render('recaptcha.html', form=capform)
        else:
            return render('loginwtf.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """The sessions shared secret will also be deleted from the
    database.
    """
    user = users.find_one({u'username': current_user.name})
    secrets = user['secrets']
    remove_us = filter(lambda secret:
                       secret['value'] == current_user.secret, secrets)
    for rm in remove_us:
        secrets.remove(rm)
        if DEBUG:
            print "Removed secret %s for user %s." % (rm['value'],
                  current_user.name)
    logout_user()
    return redirect('/')


def flash_errors(form):
    for field, errors in form.errors.items():
        for error in errors:
            flash(u"Error in the '%s' field - '%s'" % (
                getattr(form, field).label.text,
                error
            ))


@app.route('/register/activate')
def activate():
    """We'll log the user in after activation, so it is important that
    we check that it is a user that needs to be activated, so we don't
    open a hole for attacker.
    """
    username = request.args.get('username')
    activation_secret = request.args.get('activation_secret')
    user = users.find_one({u'username': username})
    # Make sure that the user is not already activated
    if ('active' not in user) or user['active']:
        return "User already activated."
    # Check if secret is ok:
    if user['activation_secret'] == activation_secret:
        # Activate user:
        act = {'active': True, 'activation': datetime.datetime.utcnow()}
        users.update({'username': username}, {'$set': act}, upsert=False)
        do_login_user(user, "", skip_password=True)
        return "AS ok."
    else:
        return "AS not ok."


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        data = add_user(form.data)
        send_registration_mail(data)
        return render('register_confirm.html', form=form)
    else:
        flash_errors(form)
    return render('register.html', form=form)


# Example of page requiring a logged in user. User will asked to login
# and then taken back here.
@app.route('/loginreq')
@login_required
def login_req():
    """The login_req decorator will only allow logged in users to access
    this method.
    """
    return render('login_req.html')


@app.route('/admin/viewuser')
def view_user():
    if not current_user.is_authenticated() \
            or not current_user.name == 'admin':
        return app.login_manager.unauthorized()
    userinfo = users.find_one({u'username': request.args.get('user')})
    return render('showall.html', userinfo=userinfo)
    #return str(user)


@app.route('/')
def index():
    return render('index.html')


if __name__ == '__main__':
    login_manager.init_app(app)
    app.config.from_object(__name__)
    app.run()
