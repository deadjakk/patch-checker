#!/usr/bin/python3
import re
from flask import Flask, request
from flask import request
from flask import render_template
import patch_checker
RE_P = 'KB[0-9]{7}';
DBFILE = 'patches.db'

app = Flask(__name__)
pcheck = patch_checker.PrivChecker(DBFILE)

@app.route("/checkprivs/", methods=["POST"])
def check_privs():
    ua = request.headers.get('User-Agent')
    if "curl/" in ua:
        ua = True
    else:
        ua = False

    KBs = re.findall(RE_P,request.form['wmicinfo'].upper())
    print("KBs:",KBs)
    result = pcheck.evaluate(KBs,request.form['build_num'],iscurl=ua)
    if ua:
        return result,200
    return render_template('results.html',message=result)
    #return result, 200

print("Starting")
@app.route("/", methods=["GET"])

def root():
    return "", 204
if __name__ == '__main__':
    app.run(host='0.0.0.0')
