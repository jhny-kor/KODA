# koda-bench: expect=vulnerable rule=code.unsafe-deserialization
import pickle as pk
from flask import request, abort
obj = pk.loads(request.data)
