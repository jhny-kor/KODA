# koda-bench: expect=clean rule=code.path-traversal
data = open("/etc/app.conf").read()
