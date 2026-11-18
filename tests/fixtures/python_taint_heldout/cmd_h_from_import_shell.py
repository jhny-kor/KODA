# koda-bench: expect=vulnerable rule=code.command-injection
from subprocess import check_output
from flask import request, abort
check_output("ls " + request.args["d"], shell=True)
