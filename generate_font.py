import urllib.request
import base64

url = "https://github.com/google/fonts/raw/main/apache/roboto/Roboto-Regular.ttf"
urllib.request.urlretrieve(url, "Roboto-Regular.ttf")

with open("Roboto-Regular.ttf", "rb") as f:
    encoded = base64.b64encode(f.read()).decode("utf-8")

with open("web/Roboto-Regular.js", "w") as f:
    f.write(f'window.ROBOTO_BASE64 = "{encoded}";\n')
