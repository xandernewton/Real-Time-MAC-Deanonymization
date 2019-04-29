from mongoDB import *




if __name__ == "__main__":

    old = "mac_research"
    database = "count_2"
    db = MongoHandler(database)
    db.clone_db(old=old, new=database)
    mongo_cursor = db._collection.find()
    for x in mongo_cursor:
        query = {'_id': x['_id']}
        update_query = {"$set": {"timestamp": round(float(x['timestamp']))}}
        db._collection.update_one(query, update_query)
