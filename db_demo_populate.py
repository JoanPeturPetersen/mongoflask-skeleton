from pymongo import MongoClient
from pymongo import ASCENDING
from pymongo.errors import DuplicateKeyError
from werkzeug.security import generate_password_hash as pwh
from prepare_db import prepare_db
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
    mongo_client = MongoClient()
    db = mongo_client.user_database
    users = db.users

    # Delete all users
    users.drop()
    prepare_db(mongo_client)
    users.ensure_index([("username", ASCENDING)], unique=True)
    #unique:true, dropDups : true
    users.insert({'username': 'Stan', 'saltedpw':pwh('123')}, safe=True)
    users.insert({'username': 'Kyle', 'saltedpw':pwh('123')}, safe=True)
    users.insert({'username': 'Eric', 'saltedpw':pwh('321')}, safe=True)
    users.insert({'username': 'Kenny', 'saltedpw':pwh('321')}, safe=True)
    try:
        users.insert({'username': 'Kenny', 'saltedpw':pwh('321')}, safe=True)
        print "Error: It seems that I can submit dublicates to the db."
    except DuplicateKeyError, e:
        print "Ok, dublicates not allowed in db."
    print
    print "These are the entries now in the user database"
    usr_sel = users.find()
    for user in usr_sel:
        print user

