# koda-bench: expect=clean rule=code.command-injection
import os
from flask import request
h = request.args["h"]
h = "localhost"
os.system("ping " + h)
