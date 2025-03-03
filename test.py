import tkinter as tk
import tkinter.ttk as ttk
from tkinter import scrolledtext
import customtkinter as ctk
from scapy.all import *
import socket
import datetime
import os
import time
import pylibpcap
import pandas as pd
import random
import numpy as np
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from keras import layers
from keras import regularizers
from keras.callbacks import EarlyStopping
from keras.layers import Dense , Dropout
from keras.models import model_from_json , load_model
from keras import initializers
from tabulate import tabulate
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler
from sklearn.model_selection import KFold
import tkinter.filedialog
from contextlib import redirect_stdout

class TextScrollCombo(ttk.Frame):

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

    # ensure a consistent GUI size
        self.grid_propagate(False)
    # implement stretchability
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

    # create a Text widget
        self.txt = tk.Text(self)
        self.txt.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)

    # create a Scrollbar and associate it with txt
        scrollb = ttk.Scrollbar(self, command=self.txt.yview)
        scrollb.grid(row=0, column=1, sticky='nsew')
        self.txt['yscrollcommand'] = scrollb.set

def summary(model: tf.keras.Model) -> str:
  summary = []
  model.summary(print_fn=lambda x: summary.append(x))
  return '\n'.join(summary)

def show_detection(y_pred):
    
    alr1 = 0
    alr2 = 0
    alr3 = 0
    
    df1 = pd.read_csv('pcaps/vmnet8.csv')
    df1.insert(loc=len(df1.columns), column='Label', value=0)
    df1['Label'] = y_pred
    df1 = df1[::-1]
    
    alr2 = df1['Label'].value_counts()[1]
    alr3 = df1['Label'].value_counts()[0]
    alr1 = alr2 + alr3
    
    df1.set_index('flow_id').T.to_dict('list')


    keys = ['protocol','timestamp','flow_duration','flow_byts_s','flow_pkts_s','fwd_pkts_s','bwd_pkts_s','tot_fwd_pkts','tot_bwd_pkts','totlen_fwd_pkts','totlen_bwd_pkts','fwd_pkt_len_max','fwd_pkt_len_min','fwd_pkt_len_mean','fwd_pkt_len_std','bwd_pkt_len_max','bwd_pkt_len_min','bwd_pkt_len_mean','bwd_pkt_len_std','pkt_len_max','pkt_len_min','pkt_len_mean','pkt_len_std','pkt_len_var','fwd_header_len','bwd_header_len','fwd_seg_size_min','fwd_act_data_pkts','flow_iat_mean','flow_iat_max','flow_iat_min','flow_iat_std','fwd_iat_tot','fwd_iat_max','fwd_iat_min','fwd_iat_mean','fwd_iat_std','bwd_iat_tot','bwd_iat_max','bwd_iat_min','bwd_iat_mean','bwd_iat_std','fwd_psh_flags','bwd_psh_flags','fwd_urg_flags','bwd_urg_flags','fin_flag_cnt','syn_flag_cnt','rst_flag_cnt','psh_flag_cnt','ack_flag_cnt','urg_flag_cnt','ece_flag_cnt','down_up_ratio','pkt_size_avg','init_fwd_win_byts','init_bwd_win_byts','active_max','active_min','active_mean','active_std','idle_max','idle_min','idle_mean','idle_std','noofpackets','packets']

    for key in keys:
        df1.pop(key)

    label_alr1_num.configure(text=str(alr1))
    label_alr2_num.configure(text=str(alr2), text_color='#A31621')
    label_alr3_num.configure(text=str(alr3))


    textf = tabulate(df1, headers = 'keys', tablefmt = 'github', showindex=False)
    comboT.delete(1.0,tk.END)
    comboT.insert(tk.END, textf)


def show_model(mod):
    textmod = summary(mod)
    comboTmod.delete(1.0,tk.END)
    comboTmod.insert(tk.END, textmod)


def detect():


    process()

    #load testing
    df = pd.read_csv('csvs/test.csv')
    X_predict = df
    #X_predict = df.drop(['Label'], axis=1)
    #Y_predict = df['Label']

    #normalization
    ms = MinMaxScaler()
    #X_predict = ms.fit_transform(X_predict)

    #Making Sample Predictions
    classes = model.predict(X_predict)

    y_pred = []
    for i in classes:
        if i > 0.5:
            y_pred.append(1)
        else:
            y_pred.append(0)

    print(y_pred)
    show_detection(y_pred)


def process():

    file2 = pd.read_csv('pcaps/vmnet8.csv')

    nbr_rows = len(file2)

    file2 = file2.drop('flow_id', axis=1)
    file2 = file2.drop('src_ip', axis=1)
    file2 = file2.drop('src_port', axis=1)
    file2 = file2.drop('dst_ip', axis=1)
    file2 = file2.drop('dst_port', axis=1)
    file2 = file2.drop('timestamp', axis=1)
    file2 = file2.drop('tot_fwd_pkts', axis=1)
    file2 = file2.drop('totlen_bwd_pkts', axis=1)
    file2 = file2.drop('fwd_pkt_len_mean', axis=1)
    file2 = file2.drop('fwd_pkt_len_std', axis=1)
    file2 = file2.drop('bwd_pkt_len_mean', axis=1)
    file2 = file2.drop('bwd_pkt_len_std', axis=1)
    file2 = file2.drop('flow_byts_s', axis=1)
    file2 = file2.drop('flow_iat_std', axis=1)
    file2 = file2.drop('flow_iat_max', axis=1)
    file2 = file2.drop('fwd_iat_mean', axis=1)
    file2 = file2.drop('fwd_iat_std', axis=1)
    file2 = file2.drop('fwd_iat_max', axis=1)
    file2 = file2.drop('bwd_iat_mean', axis=1)
    file2 = file2.drop('bwd_iat_std', axis=1)
    file2 = file2.drop('bwd_iat_max', axis=1)
    file2 = file2.drop('fwd_psh_flags', axis=1)
    file2 = file2.drop('bwd_psh_flags', axis=1)
    file2 = file2.drop('fwd_urg_flags', axis=1)
    file2 = file2.drop('bwd_urg_flags', axis=1)
    file2 = file2.drop('fwd_header_len', axis=1)
    file2 = file2.drop('bwd_header_len', axis=1)
    file2 = file2.drop('fwd_pkts_s', axis=1)
    file2 = file2.drop('pkt_len_min', axis=1)
    file2 = file2.drop('pkt_len_max', axis=1)
    file2 = file2.drop('pkt_len_mean', axis=1)
    file2 = file2.drop('pkt_len_std', axis=1)
    file2 = file2.drop('pkt_len_var', axis=1)
    file2 = file2.drop('fin_flag_cnt', axis=1)
    file2 = file2.drop('syn_flag_cnt', axis=1)
    file2 = file2.drop('rst_flag_cnt', axis=1)
    file2 = file2.drop('psh_flag_cnt', axis=1)
    file2 = file2.drop('urg_flag_cnt', axis=1)
    #file2 = file2.drop('CWE Flag Count', axis=1)
    file2 = file2.drop('ece_flag_cnt', axis=1)
    file2 = file2.drop('pkt_size_avg', axis=1)
    #file2 = file2.drop('Fwd Seg Size Avg', axis=1)
    #file2 = file2.drop('Bwd Seg Size Avg', axis=1)
    #file2 = file2.drop('Fwd Byts/b Avg', axis=1)
    #file2 = file2.drop('Fwd Pkts/b Avg', axis=1)
    #file2 = file2.drop('Fwd Blk Rate Avg', axis=1)
    #file2 = file2.drop('Bwd Byts/b Avg', axis=1)
    #file2 = file2.drop('Bwd Pkts/b Avg', axis=1)
    #file2 = file2.drop('Bwd Blk Rate Avg', axis=1)
    #file2 = file2.drop('Subflow Fwd Pkts', axis=1)
    #file2 = file2.drop('Subflow Fwd Byts', axis=1)
    #file2 = file2.drop('Subflow Bwd Pkts', axis=1)
    #file2 = file2.drop('Subflow Bwd Byts', axis=1)
    file2 = file2.drop('active_std', axis=1)
    file2 = file2.drop('active_max', axis=1)
    file2 = file2.drop('idle_mean', axis=1)
    file2 = file2.drop('idle_std', axis=1)
    file2 = file2.drop('idle_max', axis=1)
    file2 = file2.drop('idle_min', axis=1)
    #file2 = file2.drop('protocol', axis=1)
    file2 = file2.drop('noofpackets', axis=1)
    file2 = file2.drop('packets', axis=1)
    file2['protocol'] = file2['protocol'].astype(float)
    file2['flow_duration'] = file2['flow_duration'].astype(float)
    file2['tot_bwd_pkts'] = file2['tot_bwd_pkts'].astype(float)
    file2['totlen_fwd_pkts'] = file2['totlen_fwd_pkts'].astype(float)
    file2['fwd_pkt_len_min'] = file2['fwd_pkt_len_min'].astype(float)
    file2['fwd_pkt_len_max'] = file2['fwd_pkt_len_max'].astype(float)
    file2['bwd_pkt_len_max'] = file2['bwd_pkt_len_max'].astype(float)
    file2['bwd_pkt_len_min'] = file2['bwd_pkt_len_min'].astype(float)
    file2['flow_pkts_s'] = file2['flow_pkts_s'].astype(float)
    file2['flow_iat_mean'] = file2['flow_iat_mean'].astype(float)
    file2['flow_iat_min'] = file2['flow_iat_min'].astype(float)
    file2['fwd_iat_tot'] = file2['fwd_iat_tot'].astype(float)
    file2['fwd_iat_min'] = file2['fwd_iat_min'].astype(float)
    file2['bwd_iat_tot'] = file2['bwd_iat_tot'].astype(float)
    file2['bwd_iat_min'] = file2['bwd_iat_min'].astype(float)
    file2['bwd_pkts_s'] = file2['bwd_pkts_s'].astype(float)
    file2['ack_flag_cnt'] = file2['ack_flag_cnt'].astype(float)
    file2['down_up_ratio'] = file2['down_up_ratio'].astype(float)
    file2['init_fwd_win_byts'] = file2['init_fwd_win_byts'].astype(float)
    file2['init_bwd_win_byts'] = file2['init_bwd_win_byts'].astype(float)
    file2['fwd_seg_size_min'] = file2['fwd_seg_size_min'].astype(float)
    file2['active_mean'] = file2['active_mean'].astype(float)
    file2['active_min'] = file2['active_min'].astype(float)
    file2['fwd_act_data_pkts'] = file2['fwd_act_data_pkts'].astype(float)
    #file2['Label'] = file2['Label'].astype(float)

    for i in range(nbr_rows):

        if (str(file2.loc[i, "flow_pkts_s"]) == "inf"):
            file2.loc[i, "flow_pkts_s"] = random.randint(2000000,3000000)

        if (file2.loc[i, "init_fwd_win_byts"] == -1):
            file2.loc[i, "init_fwd_win_byts"] = 0

        if (file2.loc[i, "init_bwd_win_byts"] == -1):
            file2.loc[i, "init_bwd_win_byts"] = 0

    file2.to_csv('csvs/test.csv', index=False)


def capture():
    process = subprocess.Popen(['sudo', 'cicflowmeter', '-i', 'vmnet8', '-c', '--dir', 'pcaps'])
    time.sleep(30)
    process.kill()


def sched():
    global job1
    global job2
    job1 = scheduler.add_job(capture, 'interval', minutes=0.5,id='my_job1_id')
    job2 = scheduler.add_job(detect, 'interval', minutes=0.5,id='my_job2_id')


def stop():
   job1.remove()
   job2.remove()
   #scheduler.shutdown(wait=False)


def train_model():
    
    filename = tkinter.filedialog.askopenfilename(initialdir="dataset", title="Open File", filetypes=(("executables","*.csv"), ("allfiles","*.*")))

    #Read Dataset
    dataset = pd.read_csv(filename)

    dataset = dataset.head(1000)

    #Drop rows with null values
    dataset.dropna(inplace=True)

    #separating input and output attributes
    x = dataset.drop(['Label'], axis=1)
    y = dataset['Label']

    #Normalizing features
    ms = MinMaxScaler()
    x = ms.fit_transform(x)

    # K-Fold Cross Validation
    kfold = KFold(n_splits=3, shuffle=True, random_state=1)

    # Initialize an array to store the accuracy for each fold
    global fold_accuracies
    global overallacc
    global overallvalacc
    global overallloss
    global overallvalloss
    fold_accuracies = []
    overallacc = []
    overallvalacc = []
    overallloss = []
    overallvalloss = []
    j = 0

    #Deep Neural Network

    for train_index, test_index in kfold.split(x):
        X_train, X_test = x[train_index], x[test_index]
        y_train, y_test = y[train_index], y[test_index]
        j += 1

        #Defining the Deep Neural Network
        # Define and compile model
        model = keras.Sequential()

        model.add(Dense(100,input_shape=X_train.shape[1:], activation='relu',kernel_initializer=initializers.GlorotNormal(seed=None),bias_initializer=initializers.Zeros()))
        model.add(Dense(100, activation='relu'))
        model.add(Dense(100, activation='relu'))
        model.add(Dense(100, activation='relu'))
        model.add(Dropout(0.5))
        model.add(Dense(100, activation='relu'))
        model.add(Dense(1, activation='sigmoid'))
        opt = keras.optimizers.Adam(learning_rate=0.01)
        model.compile( optimizer=opt, loss="binary_crossentropy", metrics=['accuracy'])
        #model.summary()
        
        history_org = model.fit(X_train, y_train, batch_size=1000, epochs=2, verbose=2, callbacks=None, validation_data=(X_test,y_test), shuffle=True, class_weight=None, sample_weight=None, initial_epoch=0)

        for i in history_org.history['accuracy']:
            overallacc.append(i)

        for i in history_org.history['val_accuracy']:
            overallvalacc.append(i)

        for i in history_org.history['loss']:
            overallloss.append(i)

        for i in history_org.history['val_loss']:
            overallvalloss.append(i)
        # Evaluate the model on the test data
        scores = model.evaluate(X_test, y_test, verbose=0)
        fold_accuracies.append(scores[1])  # scores[1] is the accuracy
        
        textaccfold = f'Accuracy of the fold {j} : {scores[1]}\n'
        comboTmod.insert(tk.END,textaccfold)
    
    textaccfoldavg = f'Average accuracy across all folds: {np.mean(fold_accuracies)}\n'
    comboTmod.insert(tk.END,textaccfoldavg)

def clearmod():
    comboTmod.delete(1.0,tk.END)



ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

intro = ctk.CTk()
intro.title("APP")
intro.state('normal')
intro.geometry("2400x1000")


scheduler = BackgroundScheduler()
scheduler.start()

#load model 
#model = load_model('model.h5')
model = load_model('model/model-dataset-kfold.keras')

#canvas1 = tk.Canvas(intro, height=500, width=700, bg="#8EE3EF")
#canvas1.pack(fill="both", expand=True)

tabview = ctk.CTkTabview(intro)
tabview.place(relheight=0.95, relwidth=0.95, relx=0.025, rely=0.025)
tab_dash = tabview.add("Dashboard")
tab_logs = tabview.add("Logs")
tab_model = tabview.add("Model")

frame_btn_dash = ctk.CTkFrame(tab_dash)
frame_btn_dash.place(relheight=0.2, relwidth=0.95, relx=0.025, rely=0.1)

frame_alrts = ctk.CTkFrame(tab_dash)
frame_alrts.place(relheight=0.6, relwidth=0.95, relx=0.025, rely=0.3)

frame_logs = ctk.CTkFrame(tab_logs)
frame_logs.place(relheight=0.8, relwidth=0.95, relx=0.025, rely=0.1)

startB = ctk.CTkButton(frame_btn_dash, text="Start", command=sched)
startB.place(relheight=0.3, relwidth=0.2, relx=0.2, rely=0.4)

stopB = ctk.CTkButton(frame_btn_dash, text="Stop", command=stop)
stopB.place(relheight=0.3, relwidth=0.2, relx=0.6, rely=0.4)

comboT = scrolledtext.ScrolledText(frame_logs, background='#292929', foreground='white')
comboT.pack(fill="both", expand=True)
comboT.configure(width=800, height=200)

frame_alr1 = ctk.CTkFrame(frame_alrts)
frame_alr1.place(relheight=0.3, relwidth=0.2, relx=0.1, rely=0.1)
label_alr1_txt = ctk.CTkLabel(frame_alr1, text="Flows\nCaptured", fg_color="transparent", font=('Modern',15))
label_alr1_txt.place(relheight=0.9, relwidth=0.4, relx=0.05, rely=0.05)
label_alr1_sep = ctk.CTkLabel(frame_alr1, text="", fg_color="#232323")
label_alr1_sep.place(relheight=0.9, relwidth=0.01, relx=0.5, rely=0.05)
label_alr1_num = ctk.CTkLabel(frame_alr1, text="0", fg_color="transparent", font=('Modern',20))
label_alr1_num.place(relheight=0.9, relwidth=0.4, relx=0.55, rely=0.05)

frame_alr2 = ctk.CTkFrame(frame_alrts)
frame_alr2.place(relheight=0.3, relwidth=0.2, relx=0.4, rely=0.1)
label_alr2_txt = ctk.CTkLabel(frame_alr2, text="Syn attack\nDetected", fg_color="transparent", font=('Modern',15))
label_alr2_txt.place(relheight=0.9, relwidth=0.4, relx=0.05, rely=0.05)
label_alr2_sep = ctk.CTkLabel(frame_alr2, text="", fg_color="#232323")
label_alr2_sep.place(relheight=0.9, relwidth=0.01, relx=0.5, rely=0.05)
label_alr2_num = ctk.CTkLabel(frame_alr2, text="0", fg_color="transparent", font=('Modern',20))
label_alr2_num.place(relheight=0.9, relwidth=0.4, relx=0.55, rely=0.05)

frame_alr3 = ctk.CTkFrame(frame_alrts)
frame_alr3.place(relheight=0.3, relwidth=0.2, relx=0.7, rely=0.1)
label_alr3_txt = ctk.CTkLabel(frame_alr3, text="Legitimate\nFlows", fg_color="transparent", font=('Modern',15))
label_alr3_txt.place(relheight=0.9, relwidth=0.4, relx=0.05, rely=0.05)
label_alr3_sep = ctk.CTkLabel(frame_alr3, text="", fg_color="#232323")
label_alr3_sep.place(relheight=0.9, relwidth=0.01, relx=0.5, rely=0.05)
label_alr3_num = ctk.CTkLabel(frame_alr3, text="0", fg_color="transparent", font=('Modern',20))
label_alr3_num.place(relheight=0.9, relwidth=0.4, relx=0.55, rely=0.05)

frame_btn_mod = ctk.CTkFrame(tab_model)
frame_btn_mod.place(relheight=0.2, relwidth=0.95, relx=0.025, rely=0.1)

frame_mod = ctk.CTkFrame(tab_model)
frame_mod.place(relheight=0.6, relwidth=0.95, relx=0.025, rely=0.3)

showmodB = ctk.CTkButton(frame_btn_mod, text="Show model", command=lambda: show_model(model))
showmodB.place(relheight=0.3, relwidth=0.2, relx=0.2, rely=0.4)

trainmodB = ctk.CTkButton(frame_btn_mod, text="Train model", command=train_model)
trainmodB.place(relheight=0.3, relwidth=0.2, relx=0.6, rely=0.4)

clearmodB = ctk.CTkButton(frame_btn_mod, text="Clear", command=clearmod)
clearmodB.place(relheight=0.2, relwidth=0.1, relx=0.45, rely=0.45)

comboTmod = scrolledtext.ScrolledText(frame_mod, background='#292929', foreground='white')
comboTmod.pack(fill="both", expand=True)
comboTmod.configure(width=800, height=200)

intro.mainloop()