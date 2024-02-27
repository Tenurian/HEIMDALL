import tensorflow as tf
import tensorflow_decision_forests as tfdf
import tensorrt
import keras
import sqlite3 as sql
import pandas as pd

def prune_df(df):
    return df.drop(columns=[
            'filename',
            'ts',
            'uid',
            'src_ip',
            'src_port',
            'dst_ip',
            'detailed_label'
        ]).fillna({
            'dst_port'          : 0,
            'proto'             : '-',
            'service'           : '-',
            'duration'          : 0.0,
            'orig_bytes'        : 0,
            'resp_bytes'        : 0,
            'conn_state'        : '-',
            'local_orig'        : '-',
            'local_resp'        : '-',
            'missed_bytes'      : 0,
            'history'           : '-',
            'orig_pkts'         : 0,
            'orig_ip_bytes'     : 0,
            'resp_pkts'         : 0,
            'resp_ip_bytes'     : 0,
            'tunnel_parents'    : '-'
        }).astype({
            'dst_port'          : 'i',
            'proto'             : 'U',
            'service'           : 'U',
            'duration'          : 'f',
            'orig_bytes'        : 'i',
            'resp_bytes'        : 'i',
            'conn_state'        : 'U',
            'local_orig'        : 'U',
            'local_resp'        : 'U',
            'missed_bytes'      : 'i',
            'history'           : 'U',
            'orig_pkts'         : 'i',
            'orig_ip_bytes'     : 'i',
            'resp_pkts'         : 'i',
            'resp_ip_bytes'     : 'i',
            'tunnel_parents'    : 'U'
        })


try:
    conn = sql.connect(r'./.connlog.db')
    cur = conn.cursor()
    query = 'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="Malicious" ORDER BY RANDOM() LIMIT 100)'

    model = tf.keras.models.load_model('Heimdall_Basic.keras')
    model.compile(metrics=["accuracy"])

    res = pd.read_sql_query(query, conn)
    df = prune_df(res)

    print(df)

    df = df.drop(columns=['label'])

    ds = tfdf.keras.pd_dataframe_to_tf_dataset(df)

    preds = model.predict(ds)

    for pred in preds:
        # prob = tf.nn.sigmoid(pred[0])
        print(f'raw:{pred[0]} ({"benign" if pred[0] < .5 else "malicious"})')
except KeyboardInterrupt:
    print('exiting')
    exit(0)