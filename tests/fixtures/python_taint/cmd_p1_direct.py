# koda-bench: expect=vulnerable rule=code.command-injection
import os
from flask import request
os.system("ping " + request.args["host"])
