import os
from dotenv import load_dotenv
import firebase_admin
from firebase_admin import credentials, firestore

load_dotenv()
serviceaccountpath="./auth/firebasekey.json"
webapikey=os.getenv("FIREBASEWEBKEY")

#verifying valid firebase service account key
if not firebase_admin._apps:
    if os.path.exists(serviceaccountpath):
        cred=credentials.Certificate(serviceaccountpath)
        firebase_admin.initialize_app(cred)
        print("SDK Initialized!")
    else:
        raise FileNotFoundError(f"Service account file not found at: {serviceaccountpath}. ")

#Database Instance
db=firestore.client()