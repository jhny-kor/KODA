# koda-bench: expect=clean rule=code.command-injection
import os
from flask import request, abort
def f(x):
    h = request.args["h"]
    if x:
        h = "a"
    else:
        h = "b"
    os.system("ping " + h)
