import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from scipy.stats import zscore
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
import time

class handle_data():
    def __init__(self):
        self.data = None

    def handle(self, filename):
        col_names = np.array(["duration","protocol_type","service","flag","src_bytes",
            "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
            "logged_in","num_compromised","root_shell","su_attempted","num_root",
            "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
            "is_host_login","is_guest_login","count","srv_count","serror_rate",
            "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
            "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
            "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
            "dst_host_rerror_rate","dst_host_srv_rerror_rate", "class", 'difficulty level'])
        self.read_data(filename, col_names)
        self.data_defect()
        self.encode_label("protocol_type")
        self.encode_label("service")
        self.encode_label("flag")
        self.data["attack_type"] = self.data["class"].apply(self.encode_attack)
        self.data.drop(columns=['class', 'difficulty level'], inplace=True)
        # self.encode_zscore()
        return self.data

    def read_data(self, filename, col_names):
        
        self.data = pd.read_csv(filename, names = col_names)
        # print(self.data.head(10))

    def data_defect(self):
        self.data.isnull().sum()
        self.data.dropna(inplace=True, axis=1)
        self.data.drop(columns=['num_outbound_cmds', 'srv_count', 'dst_bytes', 'src_bytes', 
                                  'land', 'is_host_login', 'urgent', 'num_failed_logins', 'num_shells'], inplace=True)
        
        
    def encode_attack(self, vec):
        Dos = ['land','neptune','smurf','pod','back','teardrop']
        Probe = ['portsweep','ipsweep','satan','nmap']
        U2R = ['buffer_overflow','loadmodule','perl','rootkit']
        if vec in Dos:
            return "Dos"
        elif vec in Probe:
            return "Probe"
        elif vec in U2R:
            return "U2R"
        elif vec == "normal":
            return "Normal"
        else:
            return "R2L"
        
    def encode_label(self, label):
        label_encodeer = LabelEncoder()
        encode_label = label_encodeer.fit_transform(self.data[label])
        self.data[label] = encode_label

    def encode_zscore(self):
        cols = self.data.columns.values
        for col in cols:
            count = self.data[col].value_counts()
            for value, count in count.items():
                try:
                    if int(value) < -1 or int(value) > 1:
                        self.data[col] = zscore(self.data[col])
                        break
                except ValueError:
                    continue

def tranning(data):
    y = data[["attack_type"]]
    X = data.drop(["attack_type",],  axis=1)
    clfd = DecisionTreeClassifier(criterion ="entropy", max_depth = 4)
    start_time = time.time()
    clfd.fit(X, y.values.ravel())
    end_time = time.time()
    print("Training time: ", end_time-start_time)
    return clfd

def main():
    filename = "./NSL-KDD/KDDTrain+.txt"
    Handle = handle_data()
    data = Handle.handle(filename)
    clfd = tranning(data)
    data_test = Handle.handle("./NSL-KDD/KDDTest-21.txt")
    print(data_test.head(30))
    data_test.drop(["attack_type", ], axis=1, inplace=True)
    
    y_test = clfd.predict(data_test)
    data_test['attack-type'] = y_test
    # data_test = data_test.head(20)
    # data_test.to_excel("data.xlsx")
    print(data_test.head(30))


if __name__ == "__main__":
    main()