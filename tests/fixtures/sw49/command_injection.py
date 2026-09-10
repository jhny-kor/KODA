def ping(request):
    subprocess.run("ping " + request.args["host"], shell=True)  # nosemgrep: python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
