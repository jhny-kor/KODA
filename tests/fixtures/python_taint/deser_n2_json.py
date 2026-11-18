# koda-bench: expect=clean rule=code.unsafe-deserialization
import json
from flask import request
obj = json.loads(request.data)
