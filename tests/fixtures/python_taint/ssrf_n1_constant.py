# koda-bench: expect=clean rule=code.ssrf-user-url
import requests
r = requests.get("https://api.example.com/status")
