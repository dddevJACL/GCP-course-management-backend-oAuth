from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud import storage
import io
import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

AVATAR_PHOTO='XXXXXXXXXXXXXXXXXXXXXXX'
PASSWORD = "XXXXXXXXXXXXXXXXXX"
USERS = "users"
COURSES = "courses"
# Update the values of the following 3 variables
CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXXX'
CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXX'
DOMAIN = 'XXXXXXXXXXXXXXXXX'
# For example
# DOMAIN = 'XXXXXXXXXXXXXXX'
# Note: don't include the protocol in the value of the variable DOMAIN

ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error":  "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /courses to use this API"\

# Create a lodging if the Authorization header contains a valid JWT
@app.route('/lodgings', methods=['POST'])
def lodgings_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_lodging = datastore.entity.Entity(key=client.key("lodgings"))
        new_lodging.update({"name": content["name"], "description": content["description"],
          "price": content["price"]})
        client.put(new_lodging)
        return jsonify(id=new_lodging.key.id)
    else:
        return jsonify(error='Method not recogonized')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    content = request.get_json()
    try:
        username = content["username"]
        password = content["password"]
    except:
        return (ERROR_400, 400)
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    r_code = r.status_code
    if r_code != 200:
        return (ERROR_401, 401)
    login_response = {}
    login_response["token"] = r.json()["id_token"]
    return login_response, 200, {'Content-Type':'application/json'}


@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['POST'])
def store_avatar(id):
    # Any files in the request will be available in request.files object
    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return (ERROR_400, 400)
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requested_user = get_entity_by_id(id, USERS)
    if requested_user is None:
        return (ERROR_404, 404)
    if requested_user["sub"] != payload["sub"]:
        return (ERROR_403, 403)
    # Set file_obj to the file sent in the request
    file_obj = request.files['file']
    # If the multipart form data has a part with name 'tag', set the
    # value of the variable 'tag' to the value of 'tag' in the request.
    # Note we are not doing anything with the variable 'tag' in this
    # example, however this illustrates how we can extract data from the
    # multipart form data in addition to the files.
    if 'tag' in request.form:
        tag = request.form['tag']
    # Create a storage client
    storage_client = storage.Client()
    print(storage_client)
    # Get a handle on the bucket
    bucket = storage_client.get_bucket(AVATAR_PHOTO)
    # Create a blob object for the bucket with the name of the file
    blob = bucket.blob(file_obj.filename)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Upload the file into Cloud Storage
    blob.upload_from_file(file_obj)
    requested_user["avatar"] = file_obj.filename
    client.put(requested_user)
    return ({'avatar_url': request.url},200)


def get_entity_by_id(id, entity_type):
    """
    A generic function for searching the datastore for an id of a particular entity type.
    If the entity is found, an id attribute is added to the entity and returned.
    Otherwise, this function returns None.
    """
    entity_key = client.key(entity_type, id)
    entity = client.get(key=entity_key)
    if entity is None:
        return None
    entity["id"] = entity.key.id
    return entity


@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['GET'])
def get_avatar(file_name):
    """TODO"""
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_PHOTO)
    # Create a blob with the given file name
    blob = bucket.blob(file_name)
    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()
    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)
    # Position the file_obj to its beginning
    file_obj.seek(0)
    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)


@app.route('/images/<file_name>', methods=['DELETE'])
def delete_avatar(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_PHOTO)
    blob = bucket.blob(file_name)
    # Delete the file from Cloud Storage
    blob.delete()
    return '',204

@app.route('/' + USERS, methods=['GET'])
def get_all_users():
    """Returns all users, but only if the request comes from the admin. Otherwise 403 is returned"""
    # Verify jwt
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    datastore_query = client.query(kind=USERS)
    datastore_query.add_filter("sub", "=", payload["sub"])
    datastore_query_results = datastore_query.fetch()
    count = 0
    is_admin = False
    # return query only if user is admin
    for result in datastore_query_results:
        count += 1
        if result["role"] == "admin":
            is_admin = True
    if count == 1 and is_admin == True:
        user_query = client.query(kind=USERS)
        user_query_results = list(user_query.fetch())
        if len(user_query_results) >= 1:
            # delete any keys that arent role or sub, add id
            for result in user_query_results:
                if "avatar" in result:
                    del result["avatar"]
                result["id"] = result.key.id
        return (user_query_results, 200)
    else:
        # if not admin, return 403
        return (ERROR_403, 403)
    


@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_image(id):
    """TODO"""
    pass

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

