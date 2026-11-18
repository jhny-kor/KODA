# koda-bench: expect=vulnerable rule=code.path-traversal
import os
from flask import request
BASE = "/srv/files"
name = request.args.get("f")
p = os.path.join(BASE, name)
data = open(p).read()
