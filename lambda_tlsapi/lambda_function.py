import os
import json
import uuid
import boto3
import xmltodict
import subprocess
import validators

AWS_SERVER_PUBLIC_KEY = os.environ['AWS_SERVER_PUBLIC_KEY']
AWS_SERVER_SECRET_KEY = os.environ['AWS_SERVER_SECRET_KEY']
REGION_NAME = os.environ['REGION_NAME']
LAMBDA_FUNCTION_NAME = os.environ['LAMBDA_FUNCTION_NAME']

lambda_client = boto3.client(
    'lambda',
    aws_access_key_id=AWS_SERVER_PUBLIC_KEY,
    aws_secret_access_key=AWS_SERVER_SECRET_KEY,
    region_name=REGION_NAME
)

def is_valid_uuid(uuid_to_test, version=4):
    try:
        uuid_obj = uuid.UUID(uuid_to_test, version=version)
    except ValueError:
        return False
    return str(uuid_obj) == uuid_to_test


def is_valid_port(port_numbers):
    return_status = []
    for port_number in port_numbers:
        try:
            port = int(port_number)
            if 0 < port < 65536:
                return_status.append(True)
            else:
                return_status.append(False)
        except Exception as e:
            print(e)
            pass
            return_status.append(False)
    if False not in return_status:
        return True
    return False


def lambda_handler(event, context):
    try:
        domain_name = event.get("domain")
        port_number = event.get("port", [80, 443])
        if validators.domain(domain_name) and is_valid_port(port_number):
            # pass to lambda function
            inputParams = {
                "domain" : domain_name,
                "port" : port_number,
                "uuid" : str(uuid.uuid4())
            }

            response = lambda_client.invoke(
                FunctionName = LAMBDA_FUNCTION_NAME,
                InvocationType = 'Event',
                Payload = json.dumps(inputParams)
            )
            return {"scan_id": inputParams.get("uuid")}
    except Exception as e:
        print(e)
        pass
    return {"error": "dun goofed... figure it out yourself."}
