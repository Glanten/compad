from flask import Flask, render_template
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)

# +++ Database and MongoDB +++
# MongoDB connection
mongo_compad_uri = "mongodb+srv://compadadmin:Yu0tuPqQkPYyabr3@compadcluster00.gsqlhgd.mongodb.net/?retryWrites=true&w=majority&appName=CompadCluster00"

# Create a new client and connect to the server
client = MongoClient(mongo_compad_uri, server_api=ServerApi('1'))

# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Connection to database successful")
except Exception as mongo_error_message:
    print(mongo_error_message)

# create variable for Database
compad_db = client["compaddb"]

# create variable for characters' credits Collection
credits_collection = compad_db["credits"]

# ++++++++++++++++++++++++++++++++++++++++++++++
# +++ Flask and Webpages +++
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
    # query database for each character's credits
    gunner = credits_collection.find_one({"characterName": "gunner"})
    cassidy = credits_collection.find_one({"characterName": "cassidy"})
    glynn = credits_collection.find_one({"characterName": "glynn"})
    holt = credits_collection.find_one({"characterName": "holt"})

    return render_template("credits.html", gunner_balance=gunner["balance"], cassidy_balance=cassidy["balance"], holt_balance=holt["balance"], glynn_balance=glynn["balance"])

@app.route("/system")
def system():
    return render_template("system.html")

@app.route("/starmap")
def starmap():
    return render_template("starmap.html")

@app.route("/compad")
def compad():
    return render_template("compad.html")