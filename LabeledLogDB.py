import os
from datetime import datetime
import sqlite3 as sql
from sqlite3 import Error

import logging

from utils.ProgressBar import printProgressBar

class LabeledLogDB:
    __conn = None
    __cursor = None

    def __init__(self):
        self.__conn = sql.connect(r'./.connlog.db')
        self.__conn.row_factory = self.__dict_factory

        try:
            self.__cursor = self.__conn.cursor()
        except Error as e:
            print(f'Unable to connect to database. {e}')
            exit(1)
        pass

    def setupDB(self):
        self.__cursor.execute(
                """
CREATE TABLE IF NOT EXISTS conn_logs (
    filename text NOT NULL,
    ts real NOT NULL,
    uid text PRIMARY KEY NOT NULL,
    src_ip text NOT NULL,
    src_port int NOT NULL,
    dst_ip text NOT NULL,
    dst_port int NOT NULL,
    proto text NOT NULL,
    service text,
    duration real,
    orig_bytes int,
    resp_bytes int,
    conn_state text,
    local_orig text,
    local_resp text,
    missed_bytes int,
    history text,
    orig_pkts int,
    orig_ip_bytes int,
    resp_pkts int,
    resp_ip_bytes int,
    tunnel_parents blob,
    label text,
    detailed_label text
)
                """
            )

    def upsertLogfile(self, file):
        print(f'({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Reading {os.path.basename(file)} and updating database...')
        sql_command = f'''
INSERT INTO conn_logs(filename,ts,uid,src_ip,src_port,dst_ip,dst_port,proto,service,duration,orig_bytes,resp_bytes,conn_state,local_orig,local_resp,missed_bytes,history,orig_pkts,orig_ip_bytes,resp_pkts,resp_ip_bytes,tunnel_parents,label,detailed_label) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ON CONFLICT(uid) DO UPDATE SET filename = ?,ts = ?,src_ip = ?,src_port = ?,dst_ip = ?,dst_port = ?,proto = ?,service = ?,duration = ?,orig_bytes = ?,resp_bytes = ?,conn_state = ?,local_orig = ?,local_resp = ?,missed_bytes = ?,history = ?,orig_pkts = ?,orig_ip_bytes = ?,resp_pkts = ?,resp_ip_bytes = ?,tunnel_parents = ?,label = ?,detailed_label = ?
'''
        lines = 0
        print(f'({datetime.now().strftime("%Y-%m-%d %H:%M:%S")})\t Counting lines in file')
        with open(file, 'r') as logfile:
            lines = len(logfile.readlines())-1
        print(f'({datetime.now().strftime("%Y-%m-%d %H:%M:%S")})\t {lines} lines found.')
        print(f'({datetime.now().strftime("%Y-%m-%d %H:%M:%S")})\t Parsing file & inserting data into database')
        with open(file, 'r') as logfile:
            for i,line in enumerate(logfile):
                if not line.startswith('#'):
                    f = lambda x: x if x != '-' else None
                    fields = [f(field) for field in [os.path.basename(file).split('.')[0], *line.split()]]
                    fields_no_uid = list(fields)
                    fields_no_uid.remove(fields[2])
                    self.__cursor.execute(sql_command, [*fields, *fields_no_uid])
                    self.__conn.commit()
                printProgressBar(iteration=i, total=lines, decimals=6)
            pass
        pass

    def __dict_factory(cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d