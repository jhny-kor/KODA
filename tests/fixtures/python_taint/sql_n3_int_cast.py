# koda-bench: expect=clean rule=code.sql-dynamic-query
from flask import request
def q(cur):
    uid = int(request.args["id"])
    cur.execute(f"SELECT * FROM u WHERE id = {uid}")
