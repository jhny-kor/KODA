# koda-bench: expect=vulnerable rule=code.sql-dynamic-query
from flask import request
def q(cur):
    cur.execute(f"SELECT * FROM u WHERE id = {request.args['id']}")
