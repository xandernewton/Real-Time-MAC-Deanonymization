## Real-Time-MAC-Deanonymization

For the accompanying 3rd year project

### Main code

- real_time_deanonymization.py - initial version of the aglorithm
- real_time_deanonymization_2.py - the locality clustering algorithm
- real_time_deanonymization_3.y - global mac address algorithm
- mongoDB.py - adds probe requests from a pcap file to a MongoDB database
- recent_dictionary.py - custom dictionary implementation for the global mac address algorithm 
- mac_randomiser.py - randomises probe requests in a MongoDB collection
- global_mac_randmoiser.py - the adapted version of mac_randomiser for the global mac address algorithm

### Other code


- confusion_matrix.py - prints out pretty confusion matrices 
- convert_data.py - used to round probe requests in a MongoDB collection to the nearest timestamp for analysis


## Dataset Links

### Mac Research Dataset 
[link](https://1drv.ms/u/s!As-1LLiDPavbvEV2_JYvox_2KVx8?e=N2D2Hk)

The website hosting the mac research pcap file is down, re-hosted in the link above temporarily  



### Sapienza Dataset
[link](https://crawdad.org/sapienza/probe-requests/20130910/)

## Juypter Notebooks

Found in the juypter notebook folder, require that juypter notebooks is installed.