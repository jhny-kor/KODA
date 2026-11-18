# koda-bench: expect=vulnerable rule=code.ssrf-user-url
import requests
from flask import request, abort
r = requests.get(url=request.args["u"], timeout=5)
