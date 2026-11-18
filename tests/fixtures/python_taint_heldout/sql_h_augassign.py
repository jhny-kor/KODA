# koda-bench: expect=vulnerable rule=code.sql-dynamic-query
from flask import request, abort
def q(cur):
    sql = "SELECT * FROM t WHERE a = "
    sql += request.args["a"]
    cur.execute(sql)
