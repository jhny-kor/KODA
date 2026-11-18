# koda-bench: expect=clean rule=code.path-traversal
import re
from flask import request, abort
name = request.args["f"]
if not re.fullmatch(r"[a-z0-9]+", name):
    abort(400)
body = open("/data/" + name).read()
