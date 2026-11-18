# koda-bench: expect=clean rule=code.command-injection
import os, shlex
from flask import request
os.system("ping " + shlex.quote(request.args["h"]))
