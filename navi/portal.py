from flask import Flask, render_template, request
import sqlite3
from sqlite3 import Error
from navi.plugins.api_wrapper import request_data
import time

# locale.setlocale(locale.LC_ALL, 'en_US')

starttime = time.time()

app = Flask(__name__)


def new_db_connection(db_file):
    # create a connection to our database
    conn = None
    try:
        # A database file will be created if one doesn't exist
        conn = sqlite3.connect(db_file, timeout=30.0)
    except Error as E:
        print(E)
    return conn


@app.route('/')
def get_info():
    try:
        database = r"navi.db"
        conn = new_db_connection(database)
        with conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM assets;")

            rows = cur.fetchall()

            return render_template('index.html', rows=rows)
    except Error as e:
        print(e)


@app.route('/sqlquery/', methods=["POST"])
def get_info_by_query():
    database = r"navi.db"
    conn = new_db_connection(database)
    query = request.form['sqlstmt']
    with conn:
        cur = conn.cursor()
        cur.execute(query)

        data = cur.fetchall()

        query_info = []
        for info in data:
            query_info.append(info)

    return render_template('sqlquery.html', query_info=query_info)


@app.route('/containers/', methods=["GET"])
def get_container_info():
    cs_info = []
    data = request_data('GET', '/container-security/api/v2/images?limit=1000')

    for images in data["items"]:
        image_list = [images["name"], images["repoName"], images["tag"], images["imageHash"], images["numberOfVulns"]]
        cs_info.append(image_list)

    return render_template('containers.html', cs_info=cs_info)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000)
