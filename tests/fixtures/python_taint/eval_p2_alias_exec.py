# koda-bench: expect=vulnerable rule=code.eval-user-input
from flask import request
code = request.form.get("c")
exec(code)
