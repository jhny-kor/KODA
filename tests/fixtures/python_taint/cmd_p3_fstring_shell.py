# koda-bench: expect=vulnerable rule=code.command-injection
import subprocess
from flask import request
subprocess.run(f"ping {request.form.get('h')}", shell=True)
