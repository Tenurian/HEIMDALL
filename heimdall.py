import logging
import numpy as np
import pandas as pd
import math

import keras
from keras import layers
from keras.layers import StringLookup

import tensorflow as tf
from tensorflow import data as tf_data

import tensorflow_decision_forests as tfdf

from sklearn.preprocessing import OneHotEncoder

from LabeledLogDB import LabeledLogDB

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

    def setup_dataframes(self, LIMIT=None):

        # select_benign       = None
        # select_malicious    = None

        df = None

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
            df = pd.concat([
                malicious, 
                benign
            ]).drop(columns=[
                'filename',
                'detailed_label'
            ]).fillna({
                'ts'                : 0.0,
                'uid'               : '-',
                'src_ip'            : '-',
                'src_port'          : 0,
                'dst_ip'            : '-',
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
                'ts'                : 'f', 
                'uid'               : 'U',
                'src_ip'            : 'U',
                'src_port'          : 'i',
                'dst_ip'            : 'U',
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
        else:
            self.__LOGGER.info('Reading all logs from database and transforming results into a pandas dataframe...')
            select_all  = f'SELECT * FROM conn_logs'
            self.__LOGGER.info('querying database...')
            all         = pd.read_sql_query(select_all, self.__DATABASE.getConn())
            self.__LOGGER.info('Done')
            self.__LOGGER.info('Transforming dataframe...')
            df = all.drop(columns=[
                'filename',
                'detailed_label'
            ]).fillna({
                'ts'                : 0.0,
                'uid'               : '-',
                'src_ip'            : '-',
                'src_port'          : 0,
                'dst_ip'            : '-',
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
                'ts'                : 'f', 
                'uid'               : 'U',
                'src_ip'            : 'U',
                'src_port'          : 'i',
                'dst_ip'            : 'U',
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
            self.__LOGGER.info('Done')


        train, val, test = np.split(df.sample(frac=1), [int(0.8*len(df)), int(0.9*len(df))])

        # enc = OneHotEncoder()
        # # for cat in self.__CATEGORICAL_FEATURE_NAMES:
        # #     train[cat] = enc.fit_transform(train[cat])
        # #     val[cat]   = enc.fit_transform(  val[cat])
        # #     test[cat]  = enc.fit_transform( test[cat])

        return [train,val,test]
    
    def testing_code(self,train,val,test):
        train_ds =  tfdf.keras.pd_dataframe_to_tf_dataset(train,    label='label')
        val_ds =    tfdf.keras.pd_dataframe_to_tf_dataset(val,      label='label')
        test_ds =   tfdf.keras.pd_dataframe_to_tf_dataset(test,     label='label')

        if not self.__model:
            self.__model = tfdf.keras.RandomForestModel(
                verbose=2
            )
        self.__model.compile(metrics=["accuracy"])

        self.__model.fit(train_ds)
        loss, accuracy = self.__model.evaluate(test_ds)
        print(f'Accuracy: {accuracy}')

        # Known Malicious
        # 1547065514.872602       CgFbih6Hfauh83DUh       192.168.1.194   59106   82.76.255.62    6667    tcp     irc     9.079338        337     2462    RSTR    -       -       0       ShwAadDfr       14      917     13      2986    -   Malicious   C&C
        malicious_sample = {
            'ts': 1547065514.872602,
            'uid': 'CgFbih6Hfauh83DUh',
            'src_ip': '192.168.1.194',
            'src_port': 59106,
            'dst_ip': '82.76.255.62',
            'dst_port': 6667,
            'proto': 'tcp',
            'service': 'irc',
            'duration': 9.079338,
            'orig_bytes': 337,
            'resp_bytes': 2462,
            'conn_state': 'RSTR',
            'local_orig': '-',
            'local_resp': '-',
            'missed_bytes': 0,
            'history': 'ShwAadDfr',
            'orig_pkts': 14,
            'orig_ip_bytes': 917,
            'resp_pkts': 13,
            'resp_ip_bytes': 2986,
            'tunnel_parents': '-'
        }

        # Known Benign
        # 1547065514.852869       Cfv55W26MMly0nePie      192.168.1.194   42940   192.168.1.1     53      udp     dns     0.018234        92      171     SF      -       -       0       Dd      2       148     2       227     -   Benign   -
        benign_sample = {
            'ts': 1547065514.852869,
            'uid': 'Cfv55W26MMly0nePie',
            'src_ip': '192.168.1.194',
            'src_port': 42940,
            'dst_ip': '192.168.1.1',
            'dst_port': 53,
            'proto': 'udp',
            'service': 'dns',
            'duration': 0.018234,
            'orig_bytes': 92,
            'resp_bytes': 171,
            'conn_state': 'SF',
            'local_orig': '-',
            'local_resp': '-',
            'missed_bytes': 0,
            'history': 'Dd',
            'orig_pkts': 2,
            'orig_ip_bytes': 148,
            'resp_pkts': 2,
            'resp_ip_bytes': 227,
            'tunnel_parents': '-'
        }

        input_dict = {name: tf.convert_to_tensor([value]) for name, value in malicious_sample.items()}
        predictions = self.__model.predict(input_dict)
        prob = tf.nn.sigmoid(predictions[0])
        print(
            "The malicious sample had a %.1f percent probability "
            "of being malicious." % (100 * prob)
        )

        input_dict = {name: tf.convert_to_tensor([value]) for name, value in benign_sample.items()}
        predictions = self.__model.predict(input_dict)
        prob = tf.nn.sigmoid(predictions[0])
        print(
            "The benign sample had a %.1f percent probability "
            "of being malicious." % (100 * prob)
        )

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
    h = Heimdall()
    h.loadModel()
    for i in range(3):
        train,val,test = h.setup_dataframes(LIMIT=1000000)
        h.testing_code(train,val,test)
        h.saveModel()
    h.closeDatabase()