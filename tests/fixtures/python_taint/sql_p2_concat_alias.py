# koda-bench: expect=vulnerable rule=code.sql-dynamic-query
from flask import request
def q(cur):
    uid = request.args["id"]
    sql = "SELECT * FROM u WHERE id = " + uid
    cur.execute(sql)
