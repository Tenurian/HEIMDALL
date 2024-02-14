import logging
import numpy as np
import pandas as pd
import math

import keras
from keras import layers
from keras.layers import StringLookup

import tensorflow as tf
from tensorflow import data as tf_data

from LabeledLogDB import LabeledLogDB

from sklearn.model_selection import train_test_split

class Heimdall:
    """
    The HEIMDALL model class.
    @params:
        NUM_TREES(int)          - Maximum number of decision trees. The effective number of trained trees can be smaller if early stopping is enabled.
        MIN_EXAMPLES(int)       - Minimum number of examples in a node.
        MAX_DEPTH(int)          - Maximum depth of the tree. max_depth=1 means that all trees will be roots.
        SUBSAMPLE(float)        - Ratio of the dataset (sampling without replacement) used to train individual trees for the random sampling method.
        SAMPLING_METHOD(string) - Control the sampling of the datasets used to train individual trees.
        VALIDATION_RATIO(float) - Ratio of the training dataset used to monitor the training. Require to be >0 if early stopping is enabled.
        DATABASE(LabeledLogDB)  - The labeled Log Database that will be used for training, testing, and validation..
    """
    
    '''Columns & Their Datatypes
        filename        text    cat
        ts              float   num
        uid             text    cat
        src_ip          text    cat
        src_port        int     num
        dst_ip          text    cat
        dst_port        int     num
        proto           text    cat
        service         text    cat
        duration        float   num
        orig_bytes      int     num
        resp_bytes      int     num
        conn_state      text    cat
        local_orig      text    cat
        local_resp      text    cat
        missed_bytes    int     num
        history         text    cat
        orig_pkts       int     num
        orig_ip_bytes   int     num
        resp_pkts       int     num
        resp_ip_bytes   int     num
        tunnel_parents  blob*   cat
        ---
        label           text    label
        detailed_label  text    label
    '''
    __TARGET_COLUMN_NAME          = 'label'
    __TARGET_LABELS               = ['Malicious', 'Benign']
    # __WEIGHT_COLUMN_NAME          = None
    __NUMERIC_FEATURE_NAMES       =   [
        'ts',
        'src_port',
        'dst_port',
        'duration',
        'orig_bytes',
        'resp_bytes',
        'missed_bytes',
        'orig_pkts',
        'orig_ip_bytes',
        'resp_pkts',
        'resp_ip_bytes'
    ]
    __CATEGORICAL_FEATURE_NAMES   =   [
        'filename',
        'uid',
        'src_ip',
        'dst_ip',
        'proto',
        'service',
        'conn_state',
        'local_orig',
        'local_resp',
        'history',
        'tunnel_parents'
    ]
    
    def __init__(
        self,
        NUM_TREES = 250,
        # Maximum number of decision trees. The effective number of trained trees can be smaller if early stopping is enabled.

        MIN_EXAMPLES = 6,
        # Minimum number of examples in a node.

        MAX_DEPTH = 5,
        # Maximum depth of the tree. max_depth=1 means that all trees will be roots.

        SUBSAMPLE = 0.65,
        # Ratio of the dataset (sampling without replacement) used to train individual trees for the random sampling method.

        SAMPLING_METHOD = "RANDOM",
        # Control the sampling of the datasets used to train individual trees.

        VALIDATION_RATIO = 0.1,
        # Ratio of the training dataset used to monitor the training. Require to be >0 if early stopping is enabled.

        DATABASE = LabeledLogDB()
        # The labeled Log Database that will be used for training, testing, and validation.
    ):
        self.__NUM_TREES            = NUM_TREES
        self.__MIN_EXAMPLES         = MIN_EXAMPLES
        self.__MAX_DEPTH            = MAX_DEPTH
        self.__SUBSAMPLE            = SUBSAMPLE
        self.__SAMPLING_METHOD      = SAMPLING_METHOD
        self.__VALIDATION_RATIO     = VALIDATION_RATIO
        self.__DATABASE             = DATABASE
        self.__LOGGER = logging.getLogger('HEIMDALL')
        self.__LOGGER.info('Class loaded with provided values or defaults.')
        pass

    def __prepareDF(self, df):
        df[self.__TARGET_COLUMN_NAME] = df[self.__TARGET_COLUMN_NAME].map(
            self.__TARGET_LABELS.index
        )
        # Cast the categorical features to string.
        for feature_name in self.__CATEGORICAL_FEATURE_NAMES:
            df[feature_name] = df[feature_name].astype(str)
        pass

    # A utility method to create a tf.data dataset from a Pandas Dataframe
    def __df_to_dataset(dataframe, shuffle=True, batch_size=32):
        dataframe = dataframe.copy()
        labels = dataframe.pop('target')
        ds = tf.data.Dataset.from_tensor_slices((dict(dataframe), labels))
        if shuffle:
            ds = ds.shuffle(buffer_size=len(dataframe))
        ds = ds.batch(batch_size)
        return ds

    def setup_dataframes(self, LIMIT = 100000):
        self.__LOGGER.info(f'Reading {LIMIT} lines from database and transforming results into a pandas dataframe...')
        
        # Sql Statement to grab half the limit of malicious conn logs randomly
        select_malicious    = f'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="Malicious" ORDER BY RANDOM() LIMIT {LIMIT//2})'
        # Sql Statement to grab half the limit of benign conn logs randomly
        select_benign       = f'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="Benign" ORDER BY RANDOM() LIMIT {LIMIT//2})'

        # Run the select_malicous query and store it in the dataframe
        df = pd.read_sql_query(select_malicious, self.__DATABASE.getConn())
        # Run the select_benign query and store it in a separate dataframe
        benign = pd.read_sql_query(select_benign, self.__DATABASE.getConn()) 
        # merge the two dataframes on the uid column
        df.merge(benign, on='uid')
        # remove the filename and detailed_label columns
        df.drop(columns=['filename', 'detailed_label'])

        self.__LOGGER.info(f'df shape: {df.shape}')

        # split the dataframe into the train, test, and validation frames
        train, test = train_test_split(df, test_size=0.2)
        train, val = train_test_split(train, test_size=0.2)

        self.__LOGGER.info(f'{len(train)} train examples')
        self.__LOGGER.info(f'{len(test)} test examples')
        self.__LOGGER.info(f'{len(val)} validation examples')
        pass
    
    def closeDatabase(self):
        self.__DATABASE.close()

    def run(self):
        pass

if __name__ == "__main__":
    logging.basicConfig(level="INFO")
    h = Heimdall()
    h.setup_dataframes()
    h.closeDatabase()