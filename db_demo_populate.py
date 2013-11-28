from pymongo import Connection
from werkzeug.security import generate_password_hash as pwh
import sys

desc = """WARNING: This will delete all users in the 'user_database',
and add four new users. You can use these to experiment with the system.

To execute run the program with `GO` as an argument, like this:

    python db_demo_populate.py GO
"""                                                          

if __name__=='__main__':
    if not(len(sys.argv)==2) or not(sys.argv[-1]=='GO'):
        print desc
        sys.exit(0)
    con = Connection()
    db = con.user_database
    users = db.users

    # Delete all users
    usr_sel = users.find()
    for user in usr_sel:
        users.remove(user)

    users.insert({'username': 'Stan', 'password':pwh('123')})
    users.insert({'username': 'Kyle', 'password':pwh('123')})
    users.insert({'username': 'Eric', 'password':pwh('321')})
    users.insert({'username': 'Kenny', 'password':pwh('321')})

    print
    print "These are the entries now in the user database"
    usr_sel = users.find()
    for user in usr_sel:
        print user

