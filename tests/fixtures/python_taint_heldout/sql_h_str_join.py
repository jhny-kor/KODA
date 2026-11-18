# koda-bench: expect=vulnerable rule=code.sql-dynamic-query
from flask import request, abort
def q(cur):
    cur.execute(" ".join(["SELECT * FROM t WHERE id =", request.args["id"]]))
