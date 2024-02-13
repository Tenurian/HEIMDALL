import logging

# import json

# a = ["ts","uid","id.orig_h","id.orig_p","id.resp_h","id.resp_p","proto","service","duration","orig_bytes","resp_bytes","conn_state","local_orig","local_resp","missed_bytes","history","orig_pkts","orig_ip_bytes","resp_pkts","resp_ip_bytes","tunnel_parents","label","detailed-label"]
# b = ["time","string","addr","port","addr","port","enum","string","interval","count","count","string","bool","bool","count","string","count","count","count","count","set[string]","string","string"]
# c = {}

# for i,v, in enumerate(a):
#     c[v] = b[i]

# print(json.dumps(c, indent=2))

from LabeledLogDB import LabeledLogDB
from datetime import datetime

db = LabeledLogDB()
db.setupDB()

size_order = ['44','4','5','20','21','42','8','34','3','1','60','48','49','9','35','7','36','52','33','17','43','39']

# import os
from glob import glob

directory = r"C:\Users\thomas.feuerborn\Documents\IoT Labeled Zeek Logs"

logging.basicConfig(level='INFO')

for i,prefix in enumerate(size_order[::-1]):
    print(f'({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) file {prefix}-1 ({i+1}/{len(size_order)})')
    for file in glob(f'{directory}\\*-{prefix}-1.conn.log.labeled'):
        db.upsertLogfile(file)
        print()
    
db.close()
