# koda-bench: expect=clean rule=code.command-injection
import subprocess
from flask import request
subprocess.run(["ping", request.args["h"]])
