# koda-bench: expect=clean rule=code.eval-user-input
import ast
from flask import request
ast.literal_eval(request.args["v"])
