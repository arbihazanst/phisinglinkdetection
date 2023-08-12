import os
import json

def unique():
    json_file_path = os.path.join('.venv','Lib','site-packages','kyd','app.json')
    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)
    keyword = data.get('LOCK')
    return keyword