from pymongo import Connection

con = Connection()
db = con.user_database
users = db.users

usrs = users.find()
for user in usrs:
    for key in sorted(list(user.keys())):
        print "%20s: %s" % (key, user[key])
    print

