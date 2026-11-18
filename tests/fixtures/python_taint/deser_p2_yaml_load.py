# koda-bench: expect=vulnerable rule=code.unsafe-deserialization
import yaml
from flask import request
cfg = yaml.load(request.form.get("y"))
