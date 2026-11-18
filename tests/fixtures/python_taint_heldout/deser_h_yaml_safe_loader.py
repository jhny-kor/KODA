# koda-bench: expect=clean rule=code.unsafe-deserialization
import yaml
from flask import request, abort
cfg = yaml.load(request.data, Loader=yaml.SafeLoader)
