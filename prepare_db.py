from pymongo import MongoClient
from pymongo import ASCENDING
from werkzeug.security import generate_password_hash as pwh


def prepare_db(mongo_client):
    """Adds user `admin` and makes the `username` an unique index.
    """
    db = mongo_client.user_database
    users = db.users
    users.ensure_index([("username", ASCENDING)], unique=True)
    #unique:true, dropDups : true
    users.insert({'username': 'admin', 'saltedpw': pwh('123')}, safe=True)          
    

if __name__ == '__main__':
    mongo_client = MongoClient()
    prepare_db(mongo_client)    
