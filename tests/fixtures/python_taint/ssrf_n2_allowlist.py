# koda-bench: expect=clean rule=code.ssrf-user-url
import requests
from flask import abort
from flask import request
ALLOWED = {"https://a.example", "https://b.example"}
u = request.args["u"]
if u not in ALLOWED:
    abort(400)
r = requests.get(u)
