import boto3
import getpass
import json
from botocore.exceptions import ClientError

# =========================
# Configuration
# =========================
print("--- AWS Cognito Secure Auth Script ---")

# 1. Secure User Input
client_id = input("Client ID: ").strip()
region = input("Region: ").strip()
username = input("Username: ").strip()
password = getpass.getpass("Password: ")

# 2. Initialize Cognito Client
client = boto3.client("cognito-idp", region_name=region)

try:
    print("\n[INFO] Sending Initiate-Auth request...")
    
    # 3. Initiate Auth
    response = client.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": password
        }
    )
    print("[INFO] Initiate-Auth request sent successfully.\n")
    
    # 4. Handle Challenges (Loop handles chained challenges)
    while "ChallengeName" in response:
        challenge = response["ChallengeName"]
        session = response["Session"]
        
        match challenge:
            case "SMS_MFA":
                code = input("Enter SMS MFA Code: ").strip()
                challenge_responses = {"USERNAME": username, "SMS_MFA_CODE": code}
                
            case "SOFTWARE_TOKEN_MFA":
                code = input("Enter Authenticator App (TOTP) Code: ").strip()
                challenge_responses = {"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": code}
                
            case "NEW_PASSWORD_REQUIRED":
                print("[INFO] New password required by Cognito policy.")
                new_password = getpass.getpass("Enter New Password: ")
                challenge_responses = {"USERNAME": username, "NEW_PASSWORD": new_password}
                
            case _:
                raise ValueError(f"Unsupported or unexpected Cognito challenge: {challenge}")

        print(f"[INFO] Responding to challenge: {challenge}...")
        response = client.respond_to_auth_challenge(
            ClientId=client_id,
            ChallengeName=challenge,
            Session=session,
            ChallengeResponses=challenge_responses
        )

    # 5. Extract Tokens
    if "AuthenticationResult" in response:
        auth_result = response["AuthenticationResult"]
        print("\n[SUCCESS] Authentication complete!\n")
        
        # DevSecOps Best Practice: We store the tokens in variables.
        # We do NOT print the raw tokens to the console to prevent them 
        # from being saved in terminal history or CI/CD logs.
        # Safely extract tokens using .get() to prevent KeyError if a field is missing
        access_token = auth_result.get("AccessToken", "Not Provided")
        id_token = auth_result.get("IdToken", "Not Provided")
        refresh_token = auth_result.get("RefreshToken", "Not Issued (Check App Client Settings)")
        token_type = auth_result.get("TokenType", "Bearer")
        expires_in = auth_result.get("ExpiresIn", "Unknown")
        
        # ==========================================
        # OPT-IN TOKEN DISPLAY (Secure by Default)
        # ==========================================
        
        # Group 1: Primary Tokens
        show_primary = input("Display Access and ID Tokens? (y/n): ").strip().lower()
        if show_primary in ['y', 'yes']:
            print("\n" + "="*50)
            print(" PRIMARY TOKENS (Handle with Care)")
            print("="*50)
            print(f"ACCESS TOKEN:\n{access_token}\n")
            print(f"ID TOKEN:\n{id_token}")
            print("="*50 + "\n")
        else:
            print("\n[INFO] Primary tokens hidden for security.")

        # Group 2: Metadata and Refresh Token
        show_metadata = input("Display Refresh Token, Token Type, and Expires In? (y/n): ").strip().lower()
        if show_metadata in ['y', 'yes']:
            print("\n" + "="*50)
            print(" TOKEN METADATA & REFRESH")
            print("="*50)
            print(f"Token Type:    {token_type}")
            print(f"Expires In:    {expires_in} seconds")
            print(f"Refresh Token:\n{refresh_token}")
            print("="*50 + "\n")
        else:
            print("\n[INFO] Token metadata hidden for security.")
            
    else:
        print("\n[ERROR] Authentication completed but no AuthenticationResult was returned.")

# 6. Specific Exception Handling
except client.exceptions.NotAuthorizedException:
    print("\n[ERROR] Authentication Failed: Invalid credentials, or the App Client has a secret enabled (USER_PASSWORD_AUTH does not support secrets).")
except client.exceptions.UserNotFoundException:
    print("\n[ERROR] Authentication Failed: User does not exist.")
except ValueError as ve:
    print(f"\n[ERROR] Logic Error: {ve}")
except ClientError as e:
    print(f"\n[ERROR] AWS API Error: {e.response['Error']['Message']}")
except Exception as e:
    print(f"\n[ERROR] An unexpected error occurred: {e}")