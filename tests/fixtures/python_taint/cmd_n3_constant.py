# koda-bench: expect=clean rule=code.command-injection
import os
os.system("uptime")
