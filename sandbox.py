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

# All files
# size_order = ['44','4','5','20','21','42','8','34','3','1','60','48','49','9','35','7','36','52','33','17','43','39']

# Small files File < 0.5GB
small_files = ['44','4','5','20','21','42','8','34','3','1', '60']

# Medium files 0.5Gb <= File < 1.0Gb
medium_files = ['48','49','9']

# Large Files 1.0Gb <= File < 5.0Gb
large_files = ['35','7','36','52']

# Massive Files 5.0Gb <= File
massive_files = ['33','17','43','39']

# import os
from glob import glob

# directory = r"C:\Users\thomas.feuerborn\Documents\IoT Labeled Zeek Logs"
# directory = r"C:\Users\Spoon\Documents\IoT Labeled Zeek Logs"
directory = r"../IoT Labeled Zeek Logs"

logging.basicConfig(level='INFO')

## largest -> smallest
# for i,prefix in enumerate(size_order[::-1]):
# smallest -> largest 

order = ['small', 'medium', 'large', 'massive']

d = {
    'small': {'arr': small_files, 'desc': 'File < 0.5GB'},
    'medium': {'arr': medium_files, 'desc': '0.5Gb <= File < 1.0Gb'},
    'large': {'arr': large_files, 'desc': '1.0Gb <= File < 5.0Gb'},
    'massive': {'arr': massive_files, 'desc': '5.0Gb <= File'}
}

logger = logging.getLogger('sandbox')
# logger.info('parsing small files')

logger.info(f'Current Database Size: {db.size()}')
print()
for size in order[2::]:
    size_order = d[size]['arr']
    logger.info(f'Reading the {size} ({d[size]["desc"]}) files...')
    for i,prefix in enumerate(size_order):
        logger.info(f'\t\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) file {prefix}-1 ({i+1}/{len(size_order)})')
        # for file in glob(f'{directory}\\*-{prefix}-1.conn.log.labeled'):
        for file in glob(f'{directory}/*-{prefix}-1.conn.log.labeled'):
            # if db.countLogsFromFile(file)
            db.upsertLogfile(file)
            logger.info(db.size())
            print()
    
db.close()