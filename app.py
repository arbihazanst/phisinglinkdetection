import time
import joblib
import pickle
import warnings
from urllib import request
from flask import Flask, render_template, request
from features.code import extract_features, normalize_protocol_url, normalize_url_actual


app = Flask(__name__)

load = {
    'model': joblib.load('models/nn_model.pkl'),
}

def format_execution_time(exec_time):
    if exec_time < 60:
        return f"{exec_time:.2f} second"
    elif exec_time < 3600:
        minutes = exec_time // 60
        seconds = exec_time % 60
        return f"{minutes:.0f} minute {seconds:.2f} second"
    else:
        hours = exec_time // 3600
        minutes = (exec_time % 3600) // 60
        seconds = (exec_time % 3600) % 60
        return f"{hours:.0f} hour {minutes:.0f} minute {seconds:.2f} second"

@app.route('/', methods=['GET', 'POST'])
def home():
    results = []
    if request.method == 'POST':
        urls = []

        urls_text = request.form.get('urls')
        file = request.files.get('file')

        if urls_text:
            urls = [url.rstrip('\r') for url in urls_text.split('\n') if url.strip()]
        if file:
            file_urls_text = file.read().decode('utf-8')
            file_urls = [url.rstrip('\r') for url in file_urls_text.split('\n') if url.strip()]
            urls += file_urls
        if not urls:
            error='Please input URL or upload a file!'
            return render_template('index.html', error=error), 400
        if len(urls) > 100:
            error='Maximum 5 URLs can be inputted!'
            return render_template('index.html', error=error), 400

        for url_asli in urls:
            start_time = time.time()

            test_features = extract_features(url_asli)
            prediction = load['model'].predict([test_features]) 

            execution_time = time.time() - start_time

            result = "This URL is a phishing URL" if prediction[0] == -1 else "This URL is a legitimate URL"
            formatted_time = format_execution_time(execution_time)
            results.append((url_asli, result, formatted_time))
    return render_template('index.html', results=results)

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")
if __name__ == '__main__':
    app.run()
