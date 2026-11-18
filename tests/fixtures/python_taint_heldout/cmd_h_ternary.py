# koda-bench: expect=vulnerable rule=code.command-injection
import os
from flask import request, abort
def f(ok):
    h = request.args.get("h") if ok else "x"
    os.system("ping " + h)
