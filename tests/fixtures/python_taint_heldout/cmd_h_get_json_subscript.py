# koda-bench: expect=vulnerable rule=code.command-injection
import os
from flask import request, abort
data = request.get_json()
os.system("echo " + data["msg"])
