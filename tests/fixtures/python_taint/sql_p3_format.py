# koda-bench: expect=vulnerable rule=code.sql-dynamic-query
from flask import request
def q(cur):
    cur.execute("SELECT * FROM u WHERE n = '{}'".format(request.form.get("n")))
