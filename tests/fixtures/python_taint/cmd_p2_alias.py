# koda-bench: expect=vulnerable rule=code.command-injection
import os
from flask import request
h = request.args["host"]
cmd = "ping " + h
os.system(cmd)
