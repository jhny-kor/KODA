# koda-bench: expect=clean rule=code.unsafe-deserialization
import yaml
from flask import request
cfg = yaml.safe_load(request.form.get("y"))
