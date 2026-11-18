# koda-bench: expect=vulnerable rule=code.ssrf-user-url
import urllib.request
from flask import request
u = request.form.get("u")
r = urllib.request.urlopen(u)
