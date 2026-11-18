# koda-bench: expect=vulnerable rule=code.ssrf-user-url
import requests
from flask import request
r = requests.get(request.args["url"])
