# koda-bench: expect=vulnerable rule=code.path-traversal
from flask import request
data = open("/srv/files/" + request.args["f"]).read()
