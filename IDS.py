# Example that demonstrates going from Zeek data to scikit-learn models
import os
import sys
import argparse

# Third Party Imports
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.cluster import KMeans
from parsezeeklogs import ParseZeekLogs
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
from sklearn import preprocessing
from datetime import datetime, timedelta

import pickle
import numpy as np

# Local imports
from zat import log_to_dataframe
from zat import dataframe_to_matrix

# Helper method for scatter/beeswarm plot


def jitter(arr):
    stdev = .02*(max(arr)-min(arr))
    return arr + np.random.randn(len(arr)) * stdev

# Load model


def load_model():
    filename_U2R = "model_U2R.sav"
    loaded_model_U2R = pickle.load(open(filename_U2R, 'rb'))
    loaded_model_U2R.fit(X_U2R_test, Y_U2R_test)


def convert_time(time):
    new_time = time.total_seconds() / timedelta(days=1).total_seconds()
    return new_time


def convert_int64(value):
    if(np.isnan(value) | pd.isna(value) | value == None):
        value = 0
    else:
        value = float(value)

# def convert_float_to_int64(dataframe):
    # for values in dataframe.duration:
        # convert_int64(values)
    # for values in dataframe.orig_bytes:
        # convert_int64(values)

    #dataframe = dataframe.astype({"orig_bytes": np.float})
    # print(dataframe.dtypes)


def convert_category_to_object(dataframe):
    new_dataframe = dataframe.astype({"protocol_type": object, "service": object, "flag": object, "local_orig": object,
                                      "local_resp": object, "history": object, "tunnel_parents": object,
                                      "orig_bytes": np.float, "resp_bytes": np.float, "missed_bytes": np.float, "orig_pkts": np.float,
                                      "orig_ip_bytes": np.float, "resp_pkts": np.float, "resp_ip_bytes": np.float})
    # print(dataframe.dtypes)
    return new_dataframe


def create_column(dataframe):
    count = 0
    column = []
    value = []
    for i in range(0, 95):
        abc = str(i)

        #dataframe = dataframe.assign(abc=pd.Series(np.random.randn(len(dataframe))).values)
        #dataframe[abc] = pd.Series(np.random.randn(len(dataframe)).values)
    for i in range(0, len(dataframe)):

        value.append('0')
        print(value)

    print(dataframe)

    for i in dataframe:
        count = count + 1
    print("Count: ", count)


if __name__ == '__main__':
    # Example that demonstrates going from Zeek data to scikit-learn models

    # Collect args from the command line
    parser = argparse.ArgumentParser()
    parser.add_argument('zeek_log', type=str,
                        help='Specify a zeek log to run ZeekLogReader test on')
    args, commands = parser.parse_known_args()

    # Check for unknown args
    if commands:
        print('Unrecognized args: %s' % commands)
        sys.exit(1)

    # Sanity check that this is a dns log

    # File may have a tilde in it
    if args.zeek_log:
        args.zeek_log = os.path.expanduser(args.zeek_log)

        # Create a Pandas dataframe from the Zeek log
        log_to_df = log_to_dataframe.LogToDataFrame()
        zeek_df = log_to_df.create_dataframe(args.zeek_log)

        # Add query length
        # zeek_df['query_length'] = zeek_df['query'].str.len()

        # Normalize this field
        #ql = zeek_df['query_length']
        #zeek_df['query_length_norm'] = (ql - ql.min()) / (ql.max()-ql.min())

        # These are the features we want
        # features = ['AA', 'RA', 'RD', 'TC', 'Z', 'rejected',
        # 'proto', 'qtype_name', 'rcode_name', 'query_length']
        #feature_df = zeek_df[features]

        kdd_col_names = ["duration", "protocol_type", "service", "flag", "src_bytes",
                         "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
                         "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
                         "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
                         "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
                         "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
                         "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
                         "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
                         "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
                         "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

        col_name = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
                    "orig_bytes", "resp_bytes", "conn_state", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]

        # Convert to pandas dataframe
        log_to_df = log_to_dataframe.LogToDataFrame()
        df = log_to_df.create_dataframe(args.zeek_log)

        #df['flag'] = pd.Series('SF',index=df.index)
        # Format dataframe
        df = df.rename(columns={'proto': 'protocol_type'})
        df = df.rename(columns={'conn_state': 'flag'})
        df = df.drop("uid", axis=1)
        df = df.drop("id.orig_h", axis=1)
        df = df.drop("id.orig_p", axis=1)
        df = df.drop("id.resp_h", axis=1)
        df = df.drop("id.resp_p", axis=1)

        # Format time
        for time in df.duration:
            if (time == np.datetime64("nat")):
                time_float = 0
            else:
                time_float = float(time/np.timedelta64(1, "s"))
                if(np.isnan(time_float)):
                    time_int = 0
                else:
                    time_int = int(time_float)

            df['duration'] = df['duration'].replace([time], time_int)

        df = convert_category_to_object(df)

        for col_name in df.columns:
            if df[col_name].dtypes == 'object':
                unique_cat = len(df[col_name].unique())

        categorical_columns = ['protocol_type', 'service', 'flag']

        df_categorical_values = df[categorical_columns]

        print(df_categorical_values.head())

        # protocol type
        unique_protocol = sorted(df.protocol_type.unique())
        string1 = 'Protocol_type_'
        unique_protocol2 = [string1 + x for x in unique_protocol]
        print(unique_protocol2)

        # service
        unique_service = sorted(df.service.unique().astype(str))
        string2 = 'service_'
        unique_service2 = [string2 + x for x in unique_service]
        print(unique_service2)

        # flag
        unique_flag = sorted(df.flag.unique().astype(str))
        string3 = 'flag_'
        unique_flag2 = [string3 + x for x in unique_flag]
        print(unique_flag2)
        # print(df.head())

        # put together
        #unique_service =sorted(df.service.unique().astype(str))
        #unique_service2=[string2 + x for x in unique_service]
        dumcols = unique_protocol2 + unique_service2 + unique_flag2

        df_categorical_values_enc = df_categorical_values.apply(
            LabelEncoder().fit_transform)

        '''print(df_categorical_values)
        print('--------------------')
        print(df_categorical_values_enc)'''

        enc = OneHotEncoder(categories='auto')
        df_categorical_values_encenc = enc.fit_transform(
            df_categorical_values_enc)
        df_cat_data = pd.DataFrame(
            df_categorical_values_encenc.toarray(), columns=dumcols)

        newdf = df.join(df_cat_data)
        newdf.drop('flag', axis=1, inplace=True)
        newdf.drop('protocol_type', axis=1, inplace=True)
        newdf.drop('service', axis=1, inplace=True)
        newdf.drop('local_orig', axis=1, inplace=True)
        newdf.drop('local_resp', axis=1, inplace=True)
        newdf.drop('history', axis=1, inplace=True)
        newdf.drop('tunnel_parents', axis=1, inplace=True)

        X_DoS = newdf
        X_DoS = X_DoS.fillna(0)
        #X_DoS = X_DoS.reindex(labels=X_DoS.flag, axis=1)
        col_names = list(X_DoS)

        scaler1 = preprocessing.StandardScaler().fit(X_DoS)
        X_DoS_new = scaler1.transform(X_DoS)
        # print(X_DoS)

        X_DoS_new = np.where(np.isnan(X_DoS_new), 0, X_DoS_new)

        # Use the super awesome DataframeToMatrix class (handles categorical data!)
        #to_matrix = dataframe_to_matrix.DataFrameToMatrix()
        #zeek_matrix = to_matrix.fit_transform(feature_df)

        # Now we're ready for scikit-learn!
        # Just some simple stuff for this example, KMeans and PCA
        #kmeans = KMeans(n_clusters=5).fit_predict(zeek_matrix)
        #pca = PCA(n_components=2).fit_transform(zeek_matrix)

        # Now we can put our ML results back onto our dataframe!
        # zeek_df['x'] = jitter(pca[:, 0])  # PCA X Column
        # zeek_df['y'] = jitter(pca[:, 1])  # PCA Y Column
        #zeek_df['cluster'] = kmeans

        filename_DoS = "model_DoS.sav"
        filename_Probe = "model_Probe.sav"
        filename_R2L = "model_R2L.sav"
        filename_U2R = "model_U2R.sav"

        loaded_model_DoS = pickle.load(open(filename_DoS, 'rb'))

        loaded_model_Probe = pickle.load(open(filename_DoS, 'rb'))
        #loaded_model_Probe.fit(X_Probe_test, Y_Probe_test)

        loaded_model_R2L = pickle.load(open(filename_DoS, 'rb'))
        #loaded_model_R2L.fit(X_R2L_test, Y_R2L_test)

        loaded_model_U2R = pickle.load(open(filename_U2R, 'rb'))

        # loaded_model_DoS.predict(X_DoS)
        create_column(X_DoS)
        # Now use dataframe group by cluster
        # show_fields = ['query', 'Z', 'proto',
        #               'qtype_name', 'x', 'y', 'cluster']
        #cluster_groups = zeek_df[show_fields].groupby('cluster')

        # Now print out the details for each cluster
        #pd.set_option('display.width', 1000)
        # for key, group in cluster_groups:
        #    print('Rows in Cluster: {:d}'.format(len(group)))
        #    print(group.head(), '\n')
