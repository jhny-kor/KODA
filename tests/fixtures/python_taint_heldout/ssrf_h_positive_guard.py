# koda-bench: expect=clean rule=code.ssrf-user-url
import requests
from flask import request, abort
ALLOWED = {"https://a.example"}
u = request.args["u"]
if u in ALLOWED:
    r = requests.get(u)
