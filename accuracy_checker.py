import os
import pickle
from itertools import combinations
from confusion_matrix import *
from mongoDB import MongoHandler
from real_time_deanonymization_3 import get_frames
from pandas import DataFrame
import math


def run(n, probe_requests=None, database='mac_research_accuracy',delete=False):
    db = MongoHandler(database)
    deanonymization_obj = get_frames(n, database)

    after_clusters = deanonymization_obj._clusters
    accuracy_obj = accuracy_checker(deanonymization_obj, db)

    if not probe_requests:
        loaded_object = pickle.load(open("randomised_probe_requests_{}.dat".format(n), "rb"))
        randomised_probe_requests = loaded_object[0]
        before_clusters = loaded_object[1]
    else:
        randomised_probe_requests = probe_requests

    same_cluster_matches = []
    #sum_of_macs = sum([len(list(combinations(x,2))) for x in before_clusters.values()])
    sum_of_macs = sum([(x * (x-1)) /2 for x in before_clusters.values()])

    for cluster in after_clusters.values():
        for pair in list(combinations(cluster._matched_frames, 2)):

            if "original_mac_address" not in pair[0].keys() or "original_mac_address" not in pair[1].keys()\
                    or not check_if_random_mac(pair[0]['mac_address']) or not check_if_random_mac(pair[1]['mac_address']):
                continue
            else:
                same_cluster_matches.append(pair)

    #print("Number of randomised MAC {}".format(len(randomised_probe_requests)))


    for x, y in same_cluster_matches:

        accuracy_obj.calculate_classification(x, y)

    #total = len(list(combinations(randomised_probe_requests, 2)))
    total = (randomised_probe_requests* (randomised_probe_requests-1))/2
    P = len(same_cluster_matches)
    p_dash = sum_of_macs
    n_dash = total - p_dash

    accuracy_obj.fn = p_dash - accuracy_obj.tp
    accuracy_obj.tn = n_dash - accuracy_obj.fp

    print(accuracy_obj)
    array = np.array([[accuracy_obj.tp, accuracy_obj.fp],
                      [accuracy_obj.fn, accuracy_obj.tn]])

    plot_confusion_matrix(array)

    if delete:
        os.remove("randomised_probe_requests_{}.dat".format(n))

    accuracy_obj.calculate_metrics()
    print(accuracy_obj.metrics)
    return accuracy_obj


def plot_confusion_matrix(array):

    # get pandas dataframe
    df_cm = DataFrame(array, index=range(1, 3), columns=range(1, 3))
    # colormap: see this and choose your more dear
    cmap = 'PuRd'
    pretty_plot_confusion_matrix(df_cm, cmap=cmap)



def check_if_random_mac(mac_address):
        """

        :param string: mac_address
        :returns:
            Boolean: True if random MAC and False is not a random mac address
        """
        first_byte = mac_address[0:2]
        first_byte = int(first_byte, 16)
        return ((first_byte // 2) % 2) == 1


class accuracy_checker:

    def __init__(self, deanonymization_obj, db):

        self.clusters = deanonymization_obj._clusters
        self.tp = 0
        self.tn = 0
        self.fp = 0
        self.fn = 0
        self.db = db
        self.total = 0
        self.sensitivity = 0
        self.specificity = 0
        self.accuracy = 0
        self.precision = 0
        self.f1=0
        self.mcc = 0
        self.true = []
        self.pred = {}

        self.metrics = {}


    def __str__(self):

        return ("tp: {}\n"
                "tn: {}\n"
                "fp: {}\n"
                "fn: {}".format(self.tp, self.tn, self.fp, self.fn))

    def calculate_classification(self, x, y):

        if x['original_mac_address'] == y['original_mac_address']:
            self.tp += 1
            return
        if x['original_mac_address'] != y['original_mac_address']:
            self.fp += 1
            return

    def calculate_metrics(self):

        try:

            self.sensitivity = self.tp/(self.tp+self.fn)
            self.specificity = self.tn/(self.tn + self.fp)
            self.accuracy = (self.tp+self.tn)/(self.tn+self.tp+self.fp +self.fn)
            self.precision = self.tp/(self.tp + self.fp)
            self.f1 = (2*self.precision*self.sensitivity) / (self.precision+self.sensitivity)
            self.mcc = ((self.tp*self.tn) - (self.fp*self.fn))/math.sqrt((self.tp+self.fp)*(self.tp+self.fn)*(self.tn+self.fp)*(self.tn+self.fn))
        except ZeroDivisionError:
            pass


        self.metrics = {'tp': self.tp,
                             'tn': self.tn,
                             'fp': self.fp,
                             'fn': self.fn,
                             'sensitivity': self.sensitivity,
                             'specificity': self.specificity,
                             'accuracy': self.accuracy,
                             'precision': self.precision,
                             'f1': self.f1,
                            'mcc':self.mcc}



    def convert_to_list(self):

        tp_true = [1 for x in range(self.tp)]
        tp_pred = [1 for x in range(self.tp)]

        fn_true = [1 for x in range(self.fn)]
        fn_pred = [0 for x in range(self.fn)]

        fp_true = [0 for x in range(self.fp)]
        fp_pred = [1 for x in range(self.fp)]

        tn_true = [0 for x in range(self.tn)]
        tn_pred = [0 for x in range(self.tn)]

        self.true = tp_true + fn_true + fp_true + tn_true

        self.pred = tp_pred + fn_pred + fp_pred + tn_pred


if __name__ == "__main__":


    run(1000,database='mac_research_global')
