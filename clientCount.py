import jwt
import requests
import json
import socket
import os
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS
import logging
from datetime import datetime
import time
import certifi

def get_API_Key_and_auth():
    # Gets public key from spaces and places in correct format
    print("-- No API Key Found --")
    pubKey = requests.get(
        'https://partners.dnaspaces.eu/client/v1/partner/partnerPublicKey/')  # Change this to .io if needed
    pubKey = json.loads(pubKey.text)
    pubKey = pubKey['data'][0]['publicKey']
    pubKey = '-----BEGIN PUBLIC KEY-----\n' + pubKey + '\n-----END PUBLIC KEY-----'
    print(pubKey)

    # Gets user to paste in generated token from app
    token = input('Enter token here: ')

    # Decodes JSON Web Token to get JSON out
    decodedJWT = jwt.decode(token, pubKey, algorithms=["RS256"])
    decodedJWT = json.dumps(decodedJWT, indent=2)

    # picks up required values out of JWT
    decodedJWTJSON = json.loads(decodedJWT)
    appId = decodedJWTJSON['appId']
    activationRefId = decodedJWTJSON['activationRefId']

    # creates payloads and headers ready to activate app
    authKey = 'Bearer ' + token
    payload = {'appId': appId, 'activationRefId': activationRefId}
    header = {'Content-Type': 'application/json', 'Authorization': authKey}

    # Sends request to spaces with all info about JWT to confirm its correct, if it is, the app will show as activated
    activation = requests.post(
        'https://partners.dnaspaces.eu/client/v1/partner/activateOnPremiseApp/', headers=header, json=payload)  # Change this to .io if needed

    # pulls out activation key
    activation = json.loads(activation.text)
    apiKey = activation['data']['apiKey']

    # Writes activation key to file. This key can be used to open up Firehose connection
    f = open("API_KEY.txt", "a")
    f.write(apiKey)
    f.close()
    return apiKey

# work around to get IP address on hosts with non resolvable hostnames

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    IP_ADRRESS = s.getsockname()[0]
    s.close()
    url = 'http://' + str(IP_ADRRESS) + '/update/'
    # Define logger

    logger = logging.getLogger(__name__)

    # Set logging level
    logger.setLevel(logging.INFO)

    # define file handler and set formatter
    file_handler = logging.FileHandler('logs/clientCount{:%Y-%m-%d}.log'.format(datetime.now()))
    formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(name)s : %(message)s')
    file_handler.setFormatter(formatter)
    # add file handler to logger
    logger.addHandler(file_handler)

    # Tests to see if we already have an API Key
    try:
        if os.stat("API_KEY.txt").st_size > 0:
            # If we do, lets use it
            f = open("API_KEY.txt")
            apiKey = f.read().strip()
            f.close()
        else:
            # If not, lets get user to create one
            apiKey = get_API_Key_and_auth()
    except:
        apiKey = get_API_Key_and_auth()

    # Opens a new HTTP session that we can use to terminate firehose onto
    s = requests.Session()
    s.headers = {'X-API-Key': apiKey}



    frameResults= []
    token = "TOKE"
    org = "ORG"
    bucket = "BUCKET"
    url= "URL"
    client = influxdb_client.InfluxDBClient(
        url=url,
        org=org,
        token=token,
        ssl_ca_cert=certifi.where()
    )

    influxdbWrite_api = client.write_api(write_options=SYNCHRONOUS)

    timeout = time.time() + 5
    intervalResults = []
    clientDetails = []


    while True:
        r = s.get('https://partners.dnaspaces.eu/api/partners/v1/firehose/events', stream=True)  # Change this to .io if needed
        try:
            for line in r.iter_lines():

                if line:
                    try:
                        decoded_line = line.decode('utf-8')
                        decoded_line = decoded_line.replace("false", "\"false\"")
                        decoded_line = decoded_line.replace(" ", "")
                        event = json.loads(decoded_line)
                        # Get user/device details and write on InfluxDB
                        eventType = event['eventType']

                        # logger.info(f'Event type: {eventType}')
                        # logger.info(f"{event}")


                        if eventType == "DEVICE_COUNT":
                            cleanedData = {"measurement":"stadium","time":event["recordTimestamp"], "location":event['deviceCounts']['location']['name'], "wirelessuserCount":event['deviceCounts']['wirelessUserCount']}
                            p = influxdb_client.Point("userCount").tag("location", cleanedData["location"]).tag("timestamp",time.time()).field("clientCount",cleanedData["wirelessuserCount"])
                            try:
                                influxdbWrite_api.write(bucket=bucket, org=org, record=p)
                                intervalResults = [p]
                                logger.info('client count write to influx success!')
                            except Exception as e:
                                logger.info(f'client count write to influx failed! {e}')
                                pass



                    except Exception as e:
                        logger.info(f'line excception occured!{e}')
                        pass


        except Exception as e:
            logger.exception(f'stream get exception occured {e}')
