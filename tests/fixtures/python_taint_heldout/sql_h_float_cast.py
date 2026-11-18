# koda-bench: expect=clean rule=code.sql-dynamic-query
from flask import request, abort
def q(cur):
    price = float(request.args["p"])
    cur.execute(f"SELECT * FROM t WHERE p < {price}")
