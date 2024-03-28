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

from datetime import datetime

from utils.Spinner import Spinner,Modes

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
    def dfToDataset(dataframe, shuffle=True, batch_size=32):
        dataframe = dataframe.copy()
        labels = dataframe.pop('label')
        ds = tf_data.Dataset.from_tensor_slices((dict(dataframe), labels))
        if shuffle:
            ds = ds.shuffle(buffer_size=len(dataframe))
        ds = ds.batch(batch_size)
        return ds
    
    '''
    @staticmethod
    def getNormalizationLayer(name, dataset):
        # Create a Normalization layer for the feature.
        normalizer = layers.Normalization(axis=None)

        # Prepare a Dataset that only yields the feature.
        feature_ds = dataset.map(lambda x, y: x[name])

        # Learn the statistics of the data.
        normalizer.adapt(feature_ds)

        return normalizer
    '''
    
    '''
    @staticmethod
    def getCategoryEncodingLayer(name, dataset, dtype, max_tokens=None):
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
    '''
    
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
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Class loaded with provided values or defaults.')

    def setupDataframeByFile(self, filename, limit = 500000, page = 0):
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Querying database and setting up Dataframe')
        with Spinner(mode=Modes.Pong, suffix=f" Querying Database for up to 500,000 logs from {filename}..."):
            query = f'SELECT * FROM conn_logs WHERE filename="{filename}" LIMIT {limit} OFFSET {page*limit}'
            return self.__pruneDf(pd.read_sql_query(query, self.__DATABASE.getConn()))
        # pass
    
    def trainingCore(self, df):
        print('\n')
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Running HEIMDALL.trainingCore')
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Splitting Dataframes.')
        train, test, val = np.split(df.sample(frac=1), [int(0.8*len(df)), int(0.9*len(df))])
        train_ds =  tfdf.keras.pd_dataframe_to_tf_dataset(train,    label='label')
        test_ds =   tfdf.keras.pd_dataframe_to_tf_dataset(test,     label='label')
        val_ds =    tfdf.keras.pd_dataframe_to_tf_dataset(val,      label='label')
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Fitting the model')
        self.__model.fit(train_ds)
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Evaluating...')
        loss,accuracy = self.__model.evaluate(test_ds)
        print(f'Accuracy: {accuracy}')
        
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Validation:')
        val_res = self.__model.predict(
            val_ds,
            batch_size=None,
            verbose='auto',
            steps=None,
            callbacks=None,
            max_queue_size=10,
            workers=1,
            use_multiprocessing=False
        )

        print(val_res[-10::])
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Saving model')
        self.saveModel(version="_Full")
        pass

    def trainOnFullDatabase(self):
        LIMIT = 500000
        filelisting = self.__DATABASE.getDatabaseFileListing()
        for filename in tqdm(filelisting, unit="File", desc="Files from Database"):
            print('\n')
            file_log_count = self.__DATABASE.getLogCountByFile(filename)
            if file_log_count > LIMIT:
                for page in tqdm(range((file_log_count//LIMIT)+1), unit="Page", desc=f"Pages in File {filename}"):
                    print('\n')
                    self.trainingCore(self.setupDataframeByFile(filename=filename, limit=LIMIT, page=page))
                    print('\n')
                    pass
            else:
                self.trainingCore(self.setupDataframeByFile(filename))
            print('\n')
        pass    

    def testingCore(self,df):
        print('\n')
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Running HEIMDALL.testingCore')
        ds = tfdf.keras.pd_dataframe_to_tf_dataset(df, label='label')
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Evaluating...')
        loss,accuracy = self.__model.evaluate(ds)
        print(f'Accuracy: {accuracy}')
        pass

    def testOnFullDatabase(self):
        LIMIT = 500000
        filelisting = self.__DATABASE.getDatabaseFileListing()
        for filename in tqdm(filelisting, unit="File", desc="Files from Database"):
            print('\n')
            file_log_count = self.__DATABASE.getLogCountByFile(filename)
            if file_log_count > LIMIT:
                for page in tqdm(range((file_log_count//LIMIT)+1), unit="Page", desc=f"Pages in File {filename}"):
                    print('\n')
                    self.trainingCore(self.setupDataframeByFile(filename=filename, limit=LIMIT, page=page))
                    print('\n')
                    pass
            else:
                self.trainingCore(self.setupDataframeByFile(filename))
            print('\n')
        pass
    
    def __pruneDf(self,df,removeLabel=False):
        '''
/home/spoon/HEIMDALL/heimdall.py:279: 
    FutureWarning: Downcasting object dtype arrays on .fillna, .ffill, .bfill is deprecated and will change in a future version. 
    Call result.infer_objects(copy=False) instead. 
    To opt-in to the future behavior, set `pd.set_option('future.no_silent_downcasting', True)`
    ]).fillna({
    ...
        '''
        
        outval = df.drop(columns=[
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
        
        if removeLabel:
            outval = outval.drop(columns=['label'])
        return outval

    def closeDatabase(self):
        self.__DATABASE.close()

    def loadModel(self, version="_Basic"):
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Attempting to load Heimdall{version}.keras model from disk.')
        try:
            # self.__model = tf.keras.models.load_model('Heimdall_Basic.keras')
            self.__model = tf.keras.models.load_model(f'Heimdall{version}.keras')
            self.__model.compile(metrics=["accuracy"])
            self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Model successfully loaded from disk.')
        except:
            self.__LOGGER.error('Could not load model from disk.')
            if self.__MODE == Heimdall.Modes.RF:
                self.__model = tfdf.keras.RandomForestModel(
                    # verbose=2,
                    hyperparameter_template="benchmark_rank1"
                    # num_trees=self.__NUM_TREES,
                    # min_examples=3,
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
                self.__LOGGER.warn(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Selected mode is not supported. Exiting...\n')
                exit(1)
        pass

    def saveModel(self, version=""):
        self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Attempting to save model to disk.')
        try:
            filename = f'Heimdall{version}.keras'
            self.__model.save(filename)
            self.__LOGGER.info(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Model {filename} successfully saved to disk.')
        except:
            self.__LOGGER.error(f'\t({datetime.now().strftime("%Y-%m-%d %H:%M:%S")}) Could not save model to disk.\n')
        pass

if __name__ == "__main__":
    try:
        # print()
        # print(tfdf.keras.RandomForestModel.predefined_hyperparameters())
        # print()
        # input('Press ENTER to continue.')
        logging.basicConfig(level="INFO")
        h = Heimdall(MODE=Heimdall.Modes.RF)
        h.loadModel(version="_Full")
        # h.trainOnFullDatabase()
        h.testOnFullDatabase()
        '''
        for i in tqdm(range(5), desc="Batches", unit="batch"):
            h.loadModel()
            print()
            for i in tqdm(range(20), desc="Iterations"):
                print()
                train,val,test = h.setupRandomDataframes(LIMIT=50000)
                h.testingCode(train,val,test)
                # sleep(2)
                print()
            h.saveModel(version="_Basic")
            # sleep(5)
            print()
        '''
    except KeyboardInterrupt:
        print('Exiting...')
    finally:
        try:
            h.closeDatabase()
        except Exception:
            pass