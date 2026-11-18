# koda-bench: expect=vulnerable rule=code.eval-user-input
from flask import request
eval(request.args["expr"])
