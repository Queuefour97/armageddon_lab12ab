import json
from datetime import datetime

def lambda_handler(event, context):
    claims = event.get("requestContext", {}).get("authorizer", {}).get("claims", {})     
   
    # cognito:groups comes as a comma-separated string from API Gateway, not a list
    groups_raw = claims.get("cognito:groups", "")
    groups = groups_raw.split(",") if groups_raw else []

    
    path = event.get("resource")
    if path != "/python" and "admins" not in groups:
        return {
            "statusCode": 404,
            "body": json.dumps({"error": "Access denied, incorrect path, or no authorization"})
        }
    if path == "/python" and "admins" not in groups:
        return {
            "statusCode": 403,
            "body": json.dumps({"error": "Access denied, close but no authorization"})
        }
    else:
        print("Incoming event:", json.dumps(event))

        name = event.get("queryStringParameters", {}).get("name", "Unknown")

        response = {
            "message": f"Hello {name} from Python!rbac this is the new code that is working",
            "timestamp": datetime.utcnow().isoformat()
        }

        print("Response:", json.dumps(response))

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(response)
        }
    
    #     # RBAC logic
    
    # return {
    #     "statusCode": 200,
    #     "body": json.dumps({
    #         "message": "Access granted",
    #         "groups": groups
    #     })
    # }
    