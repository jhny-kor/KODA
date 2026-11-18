# koda-bench: expect=vulnerable rule=code.command-injection
import os
from flask import request, abort
def run(host):
    os.system("ping " + host)

run(request.args["h"])
