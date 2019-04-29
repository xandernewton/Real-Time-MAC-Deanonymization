from mongoDB import MongoHandler
import random
import pickle
from bson.objectid import ObjectId
import math

def run(n,database = 'mac_research_accuracy',old='mac_research',no_of_mac=5,all=False):

    changed_probe_requests = 0
    number_of_macs_to_change = no_of_mac
    previous_mac = None
    change_mac = True
    clusters = {}
    generated_mac_addresses = []
    db = MongoHandler(database)
    db.clone_db(old=old,new=database)
    mongo_cursor = db._collection.find()

    if all:
        number_of_macs_to_change = math.inf

    for x in mongo_cursor.limit(n):

        if number_of_macs_to_change == 0:
            change_mac = False


        if change_mac:

            if x['mac_address'] != previous_mac or number_of_macs_to_change == 5:  # used to make sure a group of sequential mac addresses with same MAC are randomised together
                number_of_macs_to_change -=1

            previous_mac = x['mac_address']

            if not check_if_random_mac(x['mac_address']):
                query = {'_id':x['_id']}
                random_mac = generate_random_mac(generated_mac_addresses)
                update_query = {"$set":{"mac_address": random_mac,
                                        "original_mac_address":x['mac_address']}}

                db._collection.update_one(query,update_query)
                new_probe_request = db._collection.find_one(ObjectId(str(x['_id'])))
                if x['mac_address'] not in clusters.keys():
                    clusters[x['mac_address']] = 1
                else:
                    clusters[x['mac_address']] +=1
                changed_probe_requests +=1

        else:

            if x['mac_address'] != previous_mac:
                number_of_macs_to_change +=1

            previous_mac = x['mac_address']

            if number_of_macs_to_change == 5:
                change_mac = True


    #print("Number of MACs changed: {}: List of ids: {}".format(len(changed_probe_requests),changed_probe_requests))
    pickle.dump([changed_probe_requests,clusters], open("randomised_probe_requests_{}.dat".format(n), "wb"))

# credit for function https://gist.github.com/pklaus/9638536
def generate_random_mac(generated_mac_addresses):

    is_random = False
    while not is_random:
        random_mac = "52:54:00:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),)
        if random_mac in generated_mac_addresses:
            continue
        else:
            is_random = True

    generated_mac_addresses.append(random_mac)
    return random_mac





def check_if_random_mac(mac_address):
        """id

        :param string: mac_address
        :returns:
            Boolean: True if random MAC and False is not a random mac address
        """

        #if mac_address[:8].upper() in self._oui_list:
         #   pass

        first_byte = mac_address[0:2]
        first_byte = int(first_byte, 16)
        return ((first_byte // 2) % 2) == 1



if __name__ == "__main__":


    run(100000, database='test',old='politics',all=True)