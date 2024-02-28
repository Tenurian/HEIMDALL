import logging
import numpy as np
import pandas as pd
import math
from time import sleep

import keras
# from keras import layers
# from keras.layers import StringLookup

import tensorflow as tf
from tensorflow import data as tf_data

import tensorflow_decision_forests as tfdf

# from sklearn.preprocessing import OneHotEncoder

from LabeledLogDB import LabeledLogDB

from tqdm import tqdm
from enum import Enum

class Heimdall:
    Modes = Enum('Modes', ['RF', 'LR', 'GBT'])
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

    # A utility method to create a tf.data dataset from a Pandas Dataframe
    @staticmethod
    def df_to_dataset(dataframe, shuffle=True, batch_size=32):
        dataframe = dataframe.copy()
        labels = dataframe.pop('label')
        ds = tf_data.Dataset.from_tensor_slices((dict(dataframe), labels))
        if shuffle:
            ds = ds.shuffle(buffer_size=len(dataframe))
        ds = ds.batch(batch_size)
        return ds
    
    @staticmethod
    def get_normalization_layer(name, dataset):
        # Create a Normalization layer for the feature.
        normalizer = layers.Normalization(axis=None)

        # Prepare a Dataset that only yields the feature.
        feature_ds = dataset.map(lambda x, y: x[name])

        # Learn the statistics of the data.
        normalizer.adapt(feature_ds)

        return normalizer
    
    @staticmethod
    def get_category_encoding_layer(name, dataset, dtype, max_tokens=None):
        # Create a layer that turns strings into integer indices.
        if dtype == 'string':
            index = layers.StringLookup(max_tokens=max_tokens)
        # Otherwise, create a layer that turns integer values into integer indices.
        else:
            index = layers.IntegerLookup(max_tokens=max_tokens)

        # Prepare a `tf.data.Dataset` that only yields the feature.
        feature_ds = dataset.map(lambda x, y: x[name])

        # Learn the set of possible values and assign them a fixed integer index.
        index.adapt(feature_ds)

        # Encode the integer indices.
        encoder = layers.CategoryEncoding(num_tokens=index.vocabulary_size())

        # Apply multi-hot encoding to the indices. The lambda function captures the
        # layer, so you can use them, or include them in the Keras Functional model later.
        return lambda feature: encoder(index(feature))
    
    ''' Columns  &  Their Datatypes
        filename        text    cat
        ts              float   num # 
        uid             text    cat
        src_ip          text    cat
        src_port        int     num
        dst_ip          text    cat
        dst_port        int     num
        proto           text    cat
        service         text    cat
        duration        float   num # 
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
        tunnel_parents  text    cat
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
        'src_ip',
        'dst_ip',
        'proto',
        'service',
        'conn_state',
        'local_orig',
        'local_resp',
        'history'
    ]
    
    def __init__(
        self,
        MODE = None,
        NUM_TREES = 4096,
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

        DATABASE = LabeledLogDB(),
        # The labeled Log Database that will be used for training, testing, and validation.
    ):
        self.__NUM_TREES            = NUM_TREES
        self.__MIN_EXAMPLES         = MIN_EXAMPLES
        self.__MAX_DEPTH            = MAX_DEPTH
        self.__SUBSAMPLE            = SUBSAMPLE
        self.__SAMPLING_METHOD      = SAMPLING_METHOD
        self.__VALIDATION_RATIO     = VALIDATION_RATIO
        self.__MODE                 = MODE if MODE else Heimdall.Modes.RF
        self.__DATABASE             = DATABASE
        self.__LOGGER = logging.getLogger('HEIMDALL')
        self.__LOGGER.info('Class loaded with provided values or defaults.')

    def setup_dataframes(self, LIMIT=10000000):

        # select_benign       = None
        # select_malicious    = None

        df = None

        print()

        if LIMIT:
            self.__LOGGER.info(f'Reading {LIMIT} lines from database and transforming results into a pandas dataframe...')
            select_malicious    = f'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="Malicious" ORDER BY RANDOM() LIMIT {LIMIT//2})'
            select_benign       = f'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="Benign" ORDER BY RANDOM() LIMIT {LIMIT//2})'
            self.__LOGGER.info('Getting malicious logs...')
            malicious   = pd.read_sql_query(select_malicious,   self.__DATABASE.getConn())
            self.__LOGGER.info('Done.')
            self.__LOGGER.info('Getting benign logs...')
            benign      = pd.read_sql_query(select_benign,      self.__DATABASE.getConn()) 
            self.__LOGGER.info('Done.')

            # remove the filename and detailed_label columns, fill null, and cast the data to appropriate types
            df = self.__prune_df(pd.concat([malicious, benign]))
        else:
            self.__LOGGER.info('Reading all logs from database and transforming results into a pandas dataframe...')
            select_all  = f'SELECT * FROM conn_logs'
            self.__LOGGER.info('querying database...')
            all         = pd.read_sql_query(select_all, self.__DATABASE.getConn())
            self.__LOGGER.info('Done')
            self.__LOGGER.info('Transforming dataframe...')
            df = self.__prune_df(all)
            self.__LOGGER.info('Done')


        train, val, test = np.split(df.sample(frac=1), [int(0.8*len(df)), int(0.9*len(df))])

        return [train,val,test]
    
    def __prune_df(self,df,removeLabel=False):
        outval = df.drop(columns=[
                'filename',
                'ts',
                'uid',
                'src_ip',
                'src_port',
                'dst_ip',
                'detailed_label'
            ]).fillna({
                # 'ts'                : 0.0,
                # 'uid'               : '-',
                # 'src_ip'            : '-',
                # 'src_port'          : 0,
                # 'dst_ip'            : '-',
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
                # 'ts'                : 'f', 
                # 'uid'               : 'U',
                # 'src_ip'            : 'U',
                # 'src_port'          : 'i',
                # 'dst_ip'            : 'U',
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
        
        if removeLabel:
            outval = outval.drop(columns=['label'])
        return outval
    
    def get_log_by_label(self,label):
        sql = f'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="{label}" ORDER BY RANDOM() LIMIT 1)'
        self.__LOGGER.info(f'Getting {label} log...')
        df = self.__prune_df(pd.read_sql_query(sql,    self.__DATABASE.getConn()), removeLabel=True)
        # print(df)
        return df.iloc[0]

    def testing_code(self,train,val,test):
        train_ds =  tfdf.keras.pd_dataframe_to_tf_dataset(train,    label='label')
        val_ds =    tfdf.keras.pd_dataframe_to_tf_dataset(val,      label='label')
        test_ds =   tfdf.keras.pd_dataframe_to_tf_dataset(test,     label='label')

        self.__model.compile(metrics=["accuracy"])
        self.__model.fit(train_ds)
        loss, accuracy = self.__model.evaluate(test_ds)
        print(f'Accuracy: {accuracy}')

        self.__LOGGER.info('\t\tTesting against Known Values')

        # Known Malicious
        malicious_sample = self.get_log_by_label('Malicious')
        mal_dict = {name: tf.convert_to_tensor([value]) for name, value in malicious_sample.items()}
        mal_prob = self.__model(mal_dict)[0][0]
        mal_prob *= 100
        print(f"The malicious sample was labeled as {'benign' if mal_prob < 50 else 'malicious'} with {mal_prob:.1f} percent certainty")

        # Known Benign
        benign_sample = self.get_log_by_label('Benign')
        ben_dict = {name: tf.convert_to_tensor([value]) for name, value in benign_sample.items()}
        ben_prob = 1-self.__model(ben_dict)[0][0]
        ben_prob *= 100
        print(f"The benign sample was labeled as {'benign' if ben_prob > 50 else 'malicious'} with {ben_prob:.1f} percent certainty")

    def closeDatabase(self):
        self.__DATABASE.close()

    def run(self):
        pass

    def loadModel(self):
        self.__LOGGER.info('Attempting to load model from disk.')
        try:
            self.__model = tf.keras.models.load_model('Heimdall_Basic.keras')
            self.__model.compile(metrics=["accuracy"])
            self.__LOGGER.info('Model successfully loaded from disk.')
        except:
            self.__LOGGER.error('Could not load model from disk.')
            if self.__MODE == Heimdall.Modes.RF:
                self.__model = tfdf.keras.RandomForestModel(
                    # verbose=2,
                    hyperparameter_template="benchmark_rank1"
                    # num_trees=self.__NUM_TREES,
                    # min_examples=self.__MIN_EXAMPLES,
                    # max_depth=self.__MAX_DEPTH,
                    # categorical_algorithm="ONE_HOT"
                )
            elif self.__MODE == Heimdall.Modes.GBT:
                self.__model = tfdf.keras.GradientBoostedTreesModel(
                    # verbose=2,
                    num_trees=self.__NUM_TREES,
                    min_examples=self.__MIN_EXAMPLES,
                    max_depth=self.__MAX_DEPTH,
                    categorical_algorithm="ONE_HOT"
                )
            else:
                self.__LOGGER.warn('Selected mode is not supported. Exiting...')
                exit(1)
        pass

    def saveModel(self):
        self.__LOGGER.info('Attempting to save model to disk.')
        try:
            self.__model.save('Heimdall_Basic.keras')
            self.__LOGGER.info('Model successfully saveed to disk.')
        except:
            self.__LOGGER.error('Could not save model to disk.')
        pass

if __name__ == "__main__":
    logging.basicConfig(level="INFO")
    h = Heimdall(MODE=Heimdall.Modes.RF)
    try:
        for i in tqdm(range(5), desc="Batches", unit="batch"):
            h.loadModel()
            print()
            for i in tqdm(range(20), desc="Iterations"):
                print()
                train,val,test = h.setup_dataframes(LIMIT=50000)
                h.testing_code(train,val,test)
                # sleep(2)
                print()
            h.saveModel()
            # sleep(5)
            print()
    except KeyboardInterrupt:
        print('exiting')
    finally:
        h.closeDatabase()
