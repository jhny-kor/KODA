# koda-bench: expect=clean rule=code.command-injection
import os
from shlex import quote
from flask import request, abort
os.system("ping " + quote(request.args["h"]))
