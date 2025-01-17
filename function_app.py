import azure.functions as func
import logging
import json
from azure.cosmos import CosmosClient
from models.user import User
import os
from datetime import datetime

# Initialize CosmosDB client using connection string
conn_str = os.environ["COSMOS_CONN_STRING"]
db_name = os.environ["COSMOS_DB_NAME"]
container_name = os.environ["COSMOS_CONTAINER_NAME"]
client = CosmosClient.from_connection_string(conn_str)
database = client.get_database_client(db_name)
container = database.get_container_client(container_name)

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

def email_exists(email: str) -> bool:
    query = "SELECT * FROM c WHERE c.email = @email"
    params = [dict(name="@email", value=email)]
    items = list(container.query_items(query=query, parameters=params, enable_cross_partition_query=True))
    return len(items) > 0

@app.route(route="user_registration", methods=["POST"])
def user_registration(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing user registration request.')

    try:
        req_body = req.get_json()
        email = req_body.get('email')
        password = req_body.get('password')

        if not email or not password:
            return func.HttpResponse(
                json.dumps({"error": "Email and password are required"}),
                status_code=400,
                mimetype="application/json"
            )

        # Check if email already exists
        if email_exists(email):
            return func.HttpResponse(
                json.dumps({"error": "Email already registered"}),
                status_code=409,
                mimetype="application/json"
            )

        # Create new user
        new_user = User(email=email, password=password)
        
        # Save to Cosmos DB
        container.create_item(body={
            "id": new_user.id,
            "email": new_user.email,
            "password": new_user.password,  # Note: In production, ensure password is hashed
            "active": new_user.active,
            "created_at": new_user.created_at.isoformat(),
            "updated_at": new_user.updated_at.isoformat()
        })

        return func.HttpResponse(
            json.dumps({"id": new_user.id, "email": new_user.email}),
            status_code=201,
            mimetype="application/json"
        )

    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid request body"}),
            status_code=400,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error creating user: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error"}),
            status_code=500,
            mimetype="application/json"
        )

@app.route(route="user_login", methods=["POST"])
def user_login(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        email = req_body.get('email')
        password = req_body.get('password')

        if not email or not password:
            return func.HttpResponse(
                json.dumps({"error": "Email and password are required"}),
                status_code=400,
                mimetype="application/json"
            )

        # Query user
        query = "SELECT * FROM c WHERE c.email = @email"
        params = [dict(name="@email", value=email)]
        items = list(container.query_items(query=query, parameters=params, enable_cross_partition_query=True))
        
        if not items or items[0]['password'] != password:  # In production, use proper password verification
            return func.HttpResponse(
                json.dumps({"error": "Invalid credentials"}),
                status_code=401,
                mimetype="application/json"
            )

        return func.HttpResponse(
            json.dumps({"id": items[0]['id'], "email": items[0]['email']}),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error during login: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error"}),
            status_code=500,
            mimetype="application/json"
        )

@app.route(route="user_profile/{user_id}", methods=["GET"])
def get_user_profile(req: func.HttpRequest) -> func.HttpResponse:
    try:
        user_id = req.route_params.get('user_id')
        user = container.read_item(item=user_id, partition_key=user_id)
        
        # Remove sensitive information
        user.pop('password', None)
        return func.HttpResponse(
            json.dumps(user),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error retrieving user profile: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "User not found"}),
            status_code=404,
            mimetype="application/json"
        )

@app.route(route="user_profile/{user_id}", methods=["PUT"])
def update_user_profile(req: func.HttpRequest) -> func.HttpResponse:
    try:
        user_id = req.route_params.get('user_id')
        updates = req.get_json()
        
        # Don't allow email or password updates through this endpoint
        updates.pop('email', None)
        updates.pop('password', None)
        
        user = container.read_item(item=user_id, partition_key=user_id)
        user.update(updates)
        user['updated_at'] = datetime.utcnow().isoformat()
        
        updated_user = container.replace_item(item=user_id, body=user)
        updated_user.pop('password', None)
        
        return func.HttpResponse(
            json.dumps(updated_user),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error updating user profile: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "User not found"}),
            status_code=404,
            mimetype="application/json"
        )