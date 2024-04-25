from pymongo import MongoClient
from pymongo.server_api import ServerApi
import urllib.parse

def connect_to_mongodb():
    # Encode special characters in the password
    password = urllib.parse.quote_plus("itachi2002")

    # Construct the MongoDB URI with encoded password
    uri = f"mongodb+srv://ig_alexios:{password}@cluster0.icskjng.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

    # Create a new client and connect to the server
    client = MongoClient(uri, server_api=ServerApi('1'))

    # Send a ping to confirm a successful connection
    try:
        client.admin.command('ping')
        print("Pinged your deployment. You successfully connected to MongoDB!")
        return client
    except Exception as e:
        print("Error:", e)
        return None
