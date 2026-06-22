import flask
from flask import Flask, render_template, request, jsonify
import os
import ScanSettings
import pickle
import json
from ScanMaker import Scanner

app = Flask(__name__)


app.secret_key = 'fj39sm3p3om3pqwm4pqm2pem[kkkkk'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan_settings', methods=['POST'])
def scan_settings():
    data = request.json
    scan_settings = ScanSettings.ScanSettings(
        url=data.get('url'),
        method=data.get('method'),
        headers=data.get('headers'),
        cookies=data.get('cookies'),
        requestbody=data.get('payload'),
        scanname=data.get('scanname')
    )
    flask.session[f'ss_{scan_settings.scanname}'] = pickle.dumps(scan_settings)

    # Возвращаем ответ
    return jsonify({
        "status": "success",
        "message": "Данные успешно получены",
        "redirect_url": f"/scanpage/{scan_settings.scanname}"
    })



@app.route('/scanpage/<string:scan_name>', methods=['GET', 'POST'])
def scan_page(scan_name):
    if request.method == 'GET':
        # Обработка GET-запроса
        if 'shell' in request.args:
            shell = request.args.get('shell')
            depth = request.args.get('depth')
            os = request.args.get('os')
            threads = request.args.get('threads')
            filename = request.args.get('filename')
            pss = flask.session.get(f'ss_{scan_name}')
            ss=pickle.loads(pss)
            scanner = Scanner(shell=shell,depth=depth,os=os,threads=threads,filename=filename,scan_settings=ss)
            print(filename)
            print(scanner.results_file)
            scanner.StartScan()

        pickle_scan_settings = flask.session.get(f'ss_{scan_name}')
        if pickle_scan_settings:
            scan_settings = pickle.loads(pickle_scan_settings)
            return render_template('scan.html', data=scan_settings)
        else:
            return "Scan settings not found.", 404

    elif request.method == 'POST':
        data = request.form
        for d in data.values():
            print(d)
        return "Data saved successfully.", 200



@app.route('/scripts/<path:script_name>')
def get_script(script_name):
    scripts_directory = 'scripts'
    file_path = os.path.join(scripts_directory, script_name)
    if not os.path.exists(file_path):
        return "Файл не найден", 404
    with open(file_path, 'r', encoding='utf-8') as file:
        script_content = file.read()
    return flask.Response(script_content, mimetype='text/javascript')

if __name__ == '__main__':
    app.run(debug=True)