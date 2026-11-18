# koda-bench: expect=vulnerable rule=code.path-traversal
from flask import request, abort
with open("/data/" + request.args["f"]) as fh:
    body = fh.read()
