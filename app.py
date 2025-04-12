from flask import Flask,render_template,request
import pandas as pd
import pickle
import re
from urllib.parse import urlparse
from sklearn.metrics import accuracy_score,confusion_matrix,precision_score,recall_score,f1_score

model = pickle.load(open("Decision_Tree_Model.pkl","rb"))
y_test = pickle.load(open("y_test.pkl","rb"))
y_pred = pickle.load(open("y_pred.pkl","rb"))

app = Flask(__name__)

@app.route('/')
def index():
    df = pd.read_csv('phishing_dataset.csv').sample(n=50)
    data = df.to_dict(orient='records')
    columns = df.columns.tolist()
    accuracy = round(accuracy_score(y_pred,y_test)*100,2)
    precision = round(precision_score(y_pred,y_test)*100,2)
    recall = round(recall_score(y_pred,y_test)*100,2)
    f1score = round(f1_score(y_pred,y_test)*100,2)
    return render_template('index.html', data=data, columns=columns,accuracy=accuracy,precision=precision,recall=recall,f1score=f1score)

def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path

    features = [
        url.count('.'),                           # NumDots
        len(url),                                 # UrlLength
        url.count('-'),                           # NumDash
        1 if '@' in url else 0,                   # AtSymbol
        1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,  # IpAddress
        1 if 'https' in hostname else 0,          # HttpsInHostname
        path.count('/'),                          # PathLevel
        len(path),                                # PathLength
        len(re.findall(r'\d', url))               # NumNumericChars
    ]
    return features


@app.route('/predict', methods=['GET', 'POST'])
def predict():
    df = pd.read_csv('phishing_dataset.csv').sample(n=50)
    data = df.to_dict(orient='records')
    columns = df.columns.tolist()
    accuracy = round(accuracy_score(y_pred,y_test)*100,2)
    precision = round(precision_score(y_pred,y_test)*100,2)
    recall = round(recall_score(y_pred,y_test)*100,2)
    f1score = round(f1_score(y_pred,y_test)*100,2)

    if request.method == 'POST':
        url = request.form.get('url')
        features = extract_features(url)
        result = model.predict([features])
        result = int(result[0]) 
        return render_template('index.html', result=result, url=url, data=data, columns=columns,accuracy=accuracy,precision=precision,recall=recall,f1score=f1score)
    return render_template('index.html', result=None, url=None, data=data, columns=columns,accuracy=accuracy,precision=precision,recall=recall,f1score=f1score)

if __name__==("__main__"):
    app.run(debug=True)