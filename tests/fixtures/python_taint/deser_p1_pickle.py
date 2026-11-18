# koda-bench: expect=vulnerable rule=code.unsafe-deserialization
import pickle
from flask import request
obj = pickle.loads(request.data)
