# koda-bench: expect=vulnerable rule=code.eval-user-input
from flask import request, abort
def a():
    return request.args["e"]

def b():
    return a()

eval(b())
