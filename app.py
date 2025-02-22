# -*- coding: utf-8 -*-

# 1. Library imports
import uvicorn
from fastapi import HTTPException, status, Security, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader, APIKeyQuery
from google.cloud import bigquery
from google.cloud import firestore
from google.oauth2 import service_account
import time
from datetime import datetime, timezone
import os
import json

api_key_query = APIKeyQuery(name="api-key", auto_error=False)
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)

json_secret = os.getenv('json_secret')

def load_credentials_from_file(json_file_path):
    with open(json_file_path) as json_file:
        credentials_info = json.load(json_file)

    # Créer l'objet Credentials avec les informations de la clé JSON
    credentials = service_account.Credentials.from_service_account_info(credentials_info)

    return credentials

def get_firestore_client(credentials):
    # Passer les credentials à l'initialisation du client Firestore
    db = firestore.Client(credentials=credentials)
    return db


def get_secret(
    api_key_query: str = Security(api_key_query),
    api_key_header: str = Security(api_key_header),
) -> str:

    if api_key_query == json_secret:
        return api_key_query
    if api_key_header == json_secret:
        return api_key_header
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired or missing secret",
    )

app = FastAPI()

# CORS Middleware Configuration
origins = [
    "http://localhost:3000",
    "https://mopsos-ai.vercel.app",
    "https://app-2-test.vercel.app",
    "https://mopsos.ai",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Index route, opens automatically on http://127.0.0.1:8000
@app.get('/')
def index():
    return {'/'}

@app.post('/api_key')
def get_api_key(secret: str = Security(get_secret), address: str = None):
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")

    json_file_path = "/etc/secrets/tranquil-lore-396810-a584b05b6b14.json"
    credentials = load_credentials_from_file(json_file_path)
    db = get_firestore_client(credentials)
    collection_ref = db.collection('collection api')

    query = collection_ref.where('address', '==', address).get()
    
    if not query:
        raise HTTPException(status_code=404, detail="No API key found for this address")
    
    user_data = query[0].to_dict()

    if user_data['expiry_date'] < int(datetime.utcnow().timestamp()):
        raise HTTPException(status_code=401, detail="API key expired")

    return {"api_key": user_data['api_key']}

@app.get('/preview')
def get_preview(secret: str = Security(get_secret)):
    credentials_path = '/etc/secrets/tranquil-lore-396810-2d54adfd3963.json'
    os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path
    client = bigquery.Client()
    query = """
    SELECT 'genomes' AS project_id, twitter_user, discord_user, telegram_user
    FROM `tranquil-lore-396810.mopsos_ai.genomes` 
    WHERE date = CURRENT_DATE() - 2

    UNION ALL

    SELECT 'anyone' AS project_id, twitter_user, discord_user, telegram_user
    FROM `tranquil-lore-396810.mopsos_ai.anyone` 
    WHERE date = CURRENT_DATE() - 2

    UNION ALL

    SELECT 'numerai' AS project_id, twitter_user, discord_user, telegram_user
    FROM `tranquil-lore-396810.mopsos_ai.numerai` 
    WHERE date = CURRENT_DATE() - 2

    UNION ALL

    SELECT 'dimitra' AS project_id, twitter_user, discord_user, telegram_user
    FROM `tranquil-lore-396810.mopsos_ai.dimitra` 
    WHERE date = CURRENT_DATE() - 2

    UNION ALL

    SELECT 'oceanprotocol' AS project_id, twitter_user, discord_user, telegram_user
    FROM `tranquil-lore-396810.mopsos_ai.ocean_protocol` 
    WHERE date = CURRENT_DATE() - 2
    """
    query_job = client.query(query)
    results = query_job.result(page_size=10000)
    rows = [dict(row) for row in results]

    return rows
    
# 5. Run the API with uvicorn
#    Will run on http://127.0.0.1:8000
if __name__ == '__main__':
    uvicorn.run(app, host='127.0.0.1', port=8000)
    
#uvicorn app:app --reload
