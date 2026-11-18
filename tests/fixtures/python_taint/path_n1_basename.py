# koda-bench: expect=clean rule=code.path-traversal
import os
from flask import request
BASE = "/srv/files"
name = os.path.basename(request.args["f"])
data = open(os.path.join(BASE, name)).read()
