#!/usr/bin/env python3
from flask import Flask, render_template, request, make_response, send_file, after_this_request
from urllib.parse import unquote
from PIL import Image
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join("uploads")
app.config['MAX_CONTENT_LENGTH'] = 1024**2
index = 'index.html'

exif_command = "exiftool -overwrite_original -all= '{}'"

@app.route('/', methods = ['GET'])
def upload():
   return render_template('index.html',error=None)

@app.route('/app.css', methods = ['GET'])
def upload_css():
   return send_file('static/app.css', mimetype='text/css')

@app.route('/bg.jpg', methods = ['GET'])
def upload_bg():
   return send_file('static/bg.jpg', mimetype='image/jpg')

@app.route('/', methods = ['POST'])
def strip_file():

    try:
        f = request.files['file']
    except:
        return render_template(index,error="File missing")

    filename = unquote(f.filename)

    if any(hack_char in filename for hack_char in ['/']):
        return render_template(index,error="Hacking attempt detected. This incident will be reported!")

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    f.save(file_path)

    @after_this_request
    def remove_file(response):
        try:
            os.remove(file_path)
        except:
            pass
        return response

    try:
        img = Image.open(file_path)
        img.verify()
    except:
        return render_template(index,error="File is not a valid image")

    return_value = os.system(exif_command.format(file_path))

    if return_value != 0:
        return render_template(index,error="Stripping EXIF data failed")

    try:
        img = Image.open(file_path)
        img.verify()
    except:
        return render_template(index,error="Result is not a valid image")

    file_handle = open(file_path,'rb')

    return send_file(file_handle,attachment_filename=filename)
        
if __name__ == '__main__':
   app.run(debug = True)
