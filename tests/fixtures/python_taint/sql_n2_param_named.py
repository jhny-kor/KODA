# koda-bench: expect=clean rule=code.sql-dynamic-query
from flask import request
def q(cur):
    cur.execute("SELECT * FROM u WHERE id = :id", {"id": request.args["id"]})
