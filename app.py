from flask import Flask, render_template

app = Flask(__name__)

# Error: 404 page
@app.errorhandler(404)
def notfound(e):
    return render_template("404.html")

# Main pages
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/credits")
def credits():
    return render_template("credits.html")

@app.route("/system")
def system():
    return render_template("system.html")

@app.route("/starmap")
def starmap():
    return render_template("starmap.html")

@app.route("/compad")
def compad():
    return render_template("compad.html")