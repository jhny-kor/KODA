# koda-bench: expect=vulnerable rule=code.command-injection
import os
from flask import request
def host():
    return request.args.get("h")

os.popen("ping " + host())
