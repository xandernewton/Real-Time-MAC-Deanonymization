from mongoDB import MongoHandler
import requests
import re
import pprint
import argparse


def load_db(n,database):

    db = MongoHandler(database)
    mongo_cursor = db._collection.find()


    for x in mongo_cursor.limit(n):
        yield x


def get_frames(n,database="mac_research",testing=False):
    deanonymization = Deanonymize()
    for x in load_db(n,database):
        deanonymization.deanonymize(x)

    for x in deanonymization._clusters.values():
        print(x)
        print(len(x))

    return deanonymization



class Cluster:
    
    def __str__(self):

        return("Cluster ID: " + str(self._cluster_id)  +", Macs in cluster:"
              + str([frame['mac_address'] for frame in self._matched_frames]))


    def __len__(self):
        return len(self._matched_frames)

    def __init__(self,cluster_id,frame):
        self._ie_fingerprint = frame['fingerprint']
        self._max_seq_number = frame['sequence_number']
        self._max_time = frame['timestamp']
        self._matched_frames = [frame]
        self._cluster_id = cluster_id

        if frame['ssid']:
            self._ssid_list = [frame['ssid']]
        else:
            self._ssid_list = []

        if 'original_mac_address' in frame.keys():
            self._cluster_mac_address = frame['original_mac_address']
        else:
            self._cluster_mac_address = frame['mac_address']


    def add_frame(self,frame):


        self._matched_frames.append(frame)
        if frame['ssid'] and frame['ssid'] not in self._ssid_list:
            self._ssid_list.append(frame['ssid'])
        self.update(frame)

    def update(self,frame):

        if not self._max_seq_number:
            self._max_seq_number = frame['sequence_number']

        elif frame['sequence_number'] > self._max_seq_number:
            self._max_seq_number = frame['sequence_number']

        if not self._max_time:
            self._max_time = frame['timestamp']

        elif frame['timestamp'] > self._max_time:
            self._max_time = frame['timestamp']



class Deanonymize:



    def __init__(self):
        self.random_mac_counter = 0
        self._clusters = {}
        self._mac_addresses = {}
        self._ssid_dict = {}
        self._cluster_id = 0
        self._number_of_non_r_macs  =0
        self._oui_list = self.get_oui_list()
        self.seq_no = 0
        self.ie_no = 0
        self.ssid_no = 0
        self.miss_no = 0

    def deanonymize(self,frame):


        mac_address  = frame['mac_address']
        is_random_mac = self.check_if_random_mac(mac_address)

        #if frame['mac_address'] in self._mac_addresses:
         #   return

        if frame['ssid']:
            if frame['ssid'] in self._ssid_dict:
                self._ssid_dict[frame['ssid']].append(frame['mac_address'])
            else:
                self._ssid_dict[frame['ssid']] = [frame['mac_address']]

        if not is_random_mac:

            if frame['mac_address'] in self._mac_addresses:
                self._clusters[self._mac_addresses[mac_address]].add_frame(frame)
            else:
                self._number_of_non_r_macs +=1
                self.create_new_cluster(frame)

        elif is_random_mac:
            cluster_found = False
            self.random_mac_counter +=1
            for cluster in self._clusters.values():
                if self.compare(frame,cluster):
                    cluster.add_frame(frame)
                    cluster_found = True
                    self._mac_addresses[mac_address] = self._cluster_id  # add the mac to our currently seen dictionary
                    return
            if not cluster_found:
                self.create_new_cluster(frame) # no match therefore create new cluster



    def create_new_cluster(self,intial_frame):

        mac_address = intial_frame['mac_address']
        self._cluster_id += 1  # increment number of clusters
        self._mac_addresses[mac_address] = self._cluster_id  # add the mac to our currently seen dictionary

        current_cluster = Cluster(self._cluster_id, intial_frame)  # create a new cluster
        self._clusters[self._cluster_id] = current_cluster  # add to our cluster dictionary


    def compare(self,frame,cluster):


        seq_number_check = self.compare_sequence_number(frame, cluster)
        ie_check = self.compare_information_elements(frame,cluster)
        ssid_check = self.compare_ssid(frame,cluster)


        if ie_check and seq_number_check:
              self.ie_no +=1
              self.seq_no +=1
              return True

        elif ssid_check:
             self.ssid_no +=1
             return True
        else:
            self.miss_no +=1
            return False


    def compare_sequence_number(self, frame,cluster, max_seq_diff=50, max_time_diff=500):

        seq_number_check = abs(frame['sequence_number'] - cluster._max_seq_number) < max_seq_diff
        if abs(frame['sequence_number'] - cluster._max_seq_number) >= 4093:
            seq_number_check = 4096 - abs(frame['sequence_number'] - cluster._max_seq_number) < max_seq_diff
        time_check = abs(float(frame['timestamp']) - float(cluster._max_time)) < max_time_diff

        if seq_number_check and time_check:
            return True
        else:
            return False

    def compare_ssid(self,frame, cluster):

        '''Check how frequently the SSID has occured
        If the SSID has appeared more than 100 times, reject as it maybe a popular SSID'''


        if frame['ssid'] in self._ssid_dict:
            if len(self._ssid_dict[frame['ssid']]) > 100:
                return False

        if frame['ssid'] in cluster._ssid_list: # ssid is not popular, check if in ssid list of cluster
            return True

        return False



    def compare_information_elements(self,frame,cluster):

        if frame['fingerprint'] == cluster._ie_fingerprint:
            return True
        else:
            return False



    def check_if_random_mac(self,mac_address):
        """

        :param string: mac_address
        :returns:
            Boolean: True if random MAC and False is not a random mac address
        """
        valid_oui = False

        if mac_address[:8].upper() in self._oui_list:
            valid_oui = True

        first_byte = mac_address[0:2]
        first_byte = int(first_byte, 16)
        return ((first_byte // 2) % 2) == 1 or not valid_oui


    def get_oui_list(self):

        oui_list = set()
        r = requests.get('https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf')
        lines = r.content.decode('utf-8').split('\n')
        for line in lines:
            if not line: # ignore blank lines
                continue
            line = line.split()
            match = re.search(r'^([0-9A-Fa-f]{2}[:-]){2}([0-9A-Fa-f]{2})$', line[0])
            if match:
                oui_list.add(line[0].upper())

        return oui_list



if __name__ == "__main__":

    get_frames(100,database='politics_accuracy')
    