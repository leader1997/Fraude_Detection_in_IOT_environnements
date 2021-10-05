from os.path import dirname, realpath, abspath, join
import numpy as np
import pickle
from flask import Flask, request, jsonify
from flask_cors import CORS
import os

app = Flask(__name__) 
CORS(app)

dir_path = os.path.dirname(os.path.abspath(__file__))
    
with open(abspath(join(dir_path, 'finalized_model.pkl')), 'rb') as f:
    rfc = pickle.load(f)
print("model RFC is on!!")

with open(abspath(join(dir_path, 'standard_scaler_props.pkl')), 'rb') as f:
    scaler = pickle.load(f)
print("scaler is on!!")
    

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    return jsonify({'is_fraude': get_pred(data)})


def get_pred(data):
    
    raw=dict()

    raw["protocol_type_icmp"]=0
    raw["protocol_type_udp"]=0
    raw["service_http"]=0
    raw["service_other"]=0
    raw["flag_RSTR"]=0
    
    
    if data["protocol_type"]=="icmp":
        raw["protocol_type_icmp"]=1
    elif data["protocol_type"]=="udp":
        raw["protocol_type_udp"]=1
    
    if data["service"]=="http":
        raw["service_http"]=1
    elif data["service"]=="other":
        raw["service_other"]=1
   
    if data["flag"]=="RSTR":
        raw["flag_RSTR"]=1

    input=[i for i in raw.values()]

    
    raw["duration"]=scaler["duration"].transform([[data["duration"]]])[0][0]
    raw["src_bytes"]=scaler["src_bytes"].transform([[data["src_bytes"]]])[0][0]
    raw["dst_bytes"]=scaler["dst_bytes"].transform([[data["dst_bytes"]]])[0][0]
        
    input=[i for i in raw.values()]

    result=rfc.predict([input])

    return int(result[0])