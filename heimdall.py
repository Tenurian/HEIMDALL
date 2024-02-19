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
        pass

    def setup_dataframes(self, LIMIT = 100000):
        self.__LOGGER.info(f'Reading {LIMIT} lines from database and transforming results into a pandas dataframe...')
        
        select_malicious    = f'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="Malicious" ORDER BY RANDOM() LIMIT {LIMIT//2})'
        select_benign       = f'SELECT * FROM conn_logs WHERE uid IN (SELECT uid FROM conn_logs WHERE label="Benign" ORDER BY RANDOM() LIMIT {LIMIT//2})'

        malicious   = pd.read_sql_query(select_malicious,   self.__DATABASE.getConn())
        benign      = pd.read_sql_query(select_benign,      self.__DATABASE.getConn()) 
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

        train, val, test = np.split(df.sample(frac=1), [int(0.8*len(df)), int(0.9*len(df))])

        return [train,val,test]
    
    def testing_code(self,train,val,test):
        # print(len(train), 'training examples')
        # print(len(val), 'validation examples')
        # print(len(test), 'test examples')

        # batch_size = 5
        # train_ds = Heimdall.df_to_dataset(train, batch_size=batch_size)

        # [(train_features, label_batch)] = train_ds.take(1)
        # print('Every feature:', list(train_features.keys()))
        # print('A batch of dst_ports:', train_features['dst_port'])
        # print('A batch of targets:', label_batch )

        # dst_port_col = train_features['dst_port']
        # layer = Heimdall.get_normalization_layer('dst_port', train_ds)
        # print(layer(dst_port_col))

        # test_proto_col = train_features['proto']
        # test_proto_layer = Heimdall.get_category_encoding_layer(
        #     name='proto',
        #     dataset=train_ds,
        #     dtype='string'
        # )
        # print(test_proto_layer(test_proto_col))

        # test_dst_port_col = train_features['dst_port']
        # test_dst_port_layer = Heimdall.get_category_encoding_layer(
        #     name='dst_port',
        #     dataset=train_ds,
        #     dtype='int64',
        #     max_tokens=5
        # )
        # print(test_dst_port_layer(test_dst_port_col))

        batch_size = 256
        train_ds =  Heimdall.df_to_dataset(train,   shuffle=False,  batch_size=batch_size)
        val_ds =    Heimdall.df_to_dataset(val,     shuffle=False,  batch_size=batch_size)
        test_ds =   Heimdall.df_to_dataset(test,    shuffle=False,  batch_size=batch_size)

        all_inputs = []
        encoded_features = []

        # Example for single numerical feature encoding
        # age_col = tf.keras.Input(shape=(1,), name='Age', dtype='int64')
        # encoding_layer = Heimdall.get_category_encoding_layer(
        #     name='Age',
        #     dataset=train_ds,
        #     dtype='int64',
        #     max_tokens=5
        # )
        # encoded_age_col = encoding_layer(age_col)
        # all_inputs.append(age_col)
        # encoded_features.append(encoded_age_col)

        # Numerical features.
        for header in self.__NUMERIC_FEATURE_NAMES:
            numeric_col = tf.keras.Input(shape=(1,), name=header)
            normalization_layer = Heimdall.get_normalization_layer(header, train_ds)
            encoded_numeric_col = normalization_layer(numeric_col)
            all_inputs.append(numeric_col)
            encoded_features.append(encoded_numeric_col)

        # Categorical features.
        for header in self.__CATEGORICAL_FEATURE_NAMES:
            categorical_col = tf.keras.Input(shape=(1,), name=header, dtype='string')
            encoding_layer = Heimdall.get_category_encoding_layer(
                name=header,
                dataset=train_ds,
                dtype='string',
                max_tokens=5
            )
            encoded_categorical_col = encoding_layer(categorical_col)
            all_inputs.append(categorical_col)
            encoded_features.append(encoded_categorical_col)
        
        # This is a testing model and will be replaced with a random forest
        all_features = tf.keras.layers.concatenate(encoded_features)
        x = tf.keras.layers.Dense(68, activation="relu")(all_features)
        x = tf.keras.layers.Dropout(0.5)(x)
        output = tf.keras.layers.Dense(1)(x)

        model = tfdf.keras.RandomForestModel(verbose=2)
        model.fit(train_ds)

        # model = tf.keras.Model(all_inputs, output)
        # model.compile(
        #     optimizer='adam',
        #     loss=tf.keras.losses.BinaryCrossentropy(from_logits=True),
        #     metrics=["accuracy"]
        # )

        # model.fit(train_ds, epochs=10, validation_data=val_ds)

        # loss, accuracy = model.evaluate(test_ds)
        # print("Accuracy", accuracy)

        model.save('Heimdall_Basic.keras')
        reloaded_model = tf.keras.models.load_model('Heimdall_Baisic.keras')

        sample = {
            'ts': 1551377744.163719,
            'uid': 'CeGuVh3VK2bqRWuQEc',
            'src_ip': '192.168.1.200',
            'src_port': 38448,
            'dst_ip': '1.1.1.1',
            'dst_port': 23,
            'proto': 'tcp',
            'service': '-',
            'duration': 3.141713,
            'orig_bytes': 0,
            'resp_bytes': 0,
            'conn_state': 'S0',
            'local_orig': '-',
            'local_resp': '-',
            'missed_bytes': 0,
            'history': 's',
            'orig_pkts': 6,
            'orig_ip_bytes': 360,
            'resp_pkts': 0,
            'resp_ip_bytes': 0,
            'tunnel_parents': '-'
        }

        input_dict = {name: tf.convert_to_tensor([value]) for name, value in sample.items()}
        predictions = reloaded_model.predict(input_dict)
        prob = tf.nn.sigmoid(predictions[0])

        print(
            "This particular log had a %.1f percent probability "
            "of being malicious." % (100 * prob)
        )

    def closeDatabase(self):
        self.__DATABASE.close()

    def run(self):
        pass

if __name__ == "__main__":
    logging.basicConfig(level="INFO")
    h = Heimdall()
    train,val,test = h.setup_dataframes()
    h.testing_code(train,val,test)
    h.closeDatabase()