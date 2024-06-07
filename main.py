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

AVATAR_PHOTO='XXXXXXXXXXXXXXX'
PASSWORD = "XXXXXXXXXXXXXXXXXXXX"
USERS = "users"
COURSES = "courses"
# Update the values of the following 3 variables
CLIENT_ID = 'XXXXXXXXXXXXXXXXXXXXXXXX'
CLIENT_SECRET = 'XXXXXXXXXXXXXXXXXXXXX'
DOMAIN = 'XXXXXXXXXXXXXXXXXXXXXXX'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error":  "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}

REQUIRED_COURSE_ATTRIBUTES = ["subject", "number", "title", "term", "instructor_id"]

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


def verify_jwt(request):
    """Verify the JWT in the request's Authorization header"""
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
    """Route of API, suggests users to access courses page to use API"""
    return "Please navigate to /courses to use this API"\


@app.route('/decode', methods=['GET'])
def decode_jwt():
    """Decode the JWT supplied in the Authorization header"""
    payload = verify_jwt(request)
    return payload          
        

@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    """
    Generate a JWT from the Auth0 domain and return it
    Request: JSON body with 2 properties with "username" and "password"
    of a user registered with this Auth0 domain
    Response: JSON with the JWT as the value of the property id_token
    """
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
    """TODO"""
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
    file_obj = request.files['file']
    if 'tag' in request.form:
        tag = request.form['tag']
    storage_client = storage.Client()
    print(storage_client)
    bucket = storage_client.get_bucket(AVATAR_PHOTO)
    blob = bucket.blob(file_obj.filename)
    file_obj.seek(0)
    blob.upload_from_file(file_obj)
    requested_user["avatar"] = file_obj.filename
    del requested_user["id"]
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
def get_avatar(id):
    """TODO"""
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requested_user = get_entity_by_id(id, USERS)
    if requested_user is None:
        return (ERROR_404, 404)
    if requested_user["sub"] != payload["sub"]:
        return (ERROR_403, 403)
    if "avatar" not in requested_user:
        return (ERROR_404, 404)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_PHOTO)
    file_name = requested_user["avatar"]
    blob = bucket.blob(file_name)
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)
    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)


@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['DELETE'])
def delete_avatar(id):
    """TODO"""
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requested_user = get_entity_by_id(id, USERS)
    if requested_user is None:
        return (ERROR_404, 404)
    if requested_user["sub"] != payload["sub"]:
        return (ERROR_403, 403)
    if "avatar" not in requested_user:
        return (ERROR_404, 404)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(AVATAR_PHOTO)
    file_name = requested_user["avatar"]
    blob = bucket.blob(file_name)
    blob.delete()
    del requested_user["avatar"]
    del requested_user["id"]
    client.put(requested_user)
    return ('', 204)

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
                if "courses" in result:
                    del result["courses"]
                result["id"] = result.key.id
        return (user_query_results, 200)
    else:
        # if not admin, return 403
        return (ERROR_403, 403)

def get_requesting_user(payload_sub):
    """Returns the entity corresponding to the user making the request, in order to help with authentication"""
    datastore_query = client.query(kind=USERS)
    datastore_query.add_filter("sub", "=", payload_sub)
    datastore_query_results = datastore_query.fetch()
    count = 0
    target_result =  None
    for result in datastore_query_results:
        count += 1
        target_result = result
    if count == 1:
        target_result["id"] = target_result.key.id
        return target_result
    return None

def get_query_list_where_a_equals_b(a, b, kind):
    """Generic function that returns a list of entities that match the desired query"""
    datastore_query = client.query(kind=kind)
    datastore_query.add_filter(a, "=", b)
    datastore_query_results = datastore_query.fetch()
    result_list = list()
    for result in datastore_query_results:
        result["id"] = result.key.id
        result_list.append(result)
    return result_list


@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_user(id):
    """
    Returns given user, but only if the request comes from the admin, or the id matches jwt of same user.
    Otherwise 403 is returned
    """
    # Verify jwt
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requesting_user = get_requesting_user(payload["sub"])
    requested_user = get_entity_by_id(id, USERS)
    if requested_user is None:
        return (ERROR_403, 403)
    if requesting_user["role"] != "admin" and payload["sub"] != requested_user["sub"]:
        return (ERROR_403, 403)
    if "avatar" in requested_user:
        requested_user["avatar_url"] = request.base_url + "/avatar"
        del requested_user["avatar"]
    if requested_user["role"] != "admin":
        if "courses" not in requested_user:
            requested_user["courses"] = list()
        stored_course_list = requested_user["courses"]
        requested_user["courses"] = list()
        base_url = request.base_url.split("users")
        base_url = base_url[0]
        for course in stored_course_list:
            requested_user["courses"].append(base_url + "/courses/" + str(course))
    return (requested_user, 200) #?

def validate_course_create_request(request_json, required_attributes):
    """Validates that course create request has all required attributes"""
    for attribute in required_attributes:
        if attribute not in request_json:
            return False
    instructor_id = request_json["instructor_id"]
    instructor = get_entity_by_id(instructor_id, USERS)
    if instructor is None or instructor["role"] != "instructor":
        return False
    return True

@app.route('/' + COURSES, methods=['POST'])
def create_course():
    """
    Creates a course with the given attributes, only if the requester is admin. If JWT is invalid or missing,
    401 is returned. If the requester is not admin, 403 is returned. If any attributes are missing, or the instructor_id
    is invalid, 400 is returned.
    """
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requesting_user = get_requesting_user(payload["sub"])
    if requesting_user["role"] != "admin":
        return (ERROR_403, 403)
    content = request.get_json()
    valid_request = validate_course_create_request(content, REQUIRED_COURSE_ATTRIBUTES)
    if not valid_request:
        return (ERROR_400, 400)
    new_course = datastore.entity.Entity(key=client.key(COURSES))
    new_course.update(create_post_or_update_dict(content, REQUIRED_COURSE_ATTRIBUTES))
    client.put(new_course)
    instructor_id = content["instructor_id"]
    instructor = get_entity_by_id(instructor_id, USERS)
    if "courses" in instructor:
        instructor["courses"].append(new_course.key.id)
        del instructor["id"]
        client.put(instructor)
    else:
        course_list = list()
        course_list.append(new_course.key.id)
        instructor["courses"] = course_list
        del instructor["id"]
        client.put(instructor)
    new_course["id"] = new_course.key.id
    new_course["self"] = request.base_url + "/" + str(new_course.key.id)
    return (new_course, 201)


def create_post_or_update_dict(request_json, required_attributes, entity_dict=None):
    """
    Creates a dict object for entities used for the post or update method in posting to datastore
    """
    if entity_dict is None:
        entity_dict = dict()
    for attribute in required_attributes:
        if attribute in request_json:
            entity_dict[attribute] = request_json[attribute]
    return entity_dict
    

@app.route('/' + COURSES, methods=['GET'])
def get_all_courses():
    """Returns all courses, paginated based on given limit/offset params, with a default of 3."""
    offset = request.args.get("offset")
    limit = request.args.get("limit")
    if offset is None:
        offset = 0
    if limit is None:
        limit = 3
    courses_query = client.query(kind=COURSES)
    courses_query.order = ["subject"]
    courses_iterator = courses_query.fetch(limit=int(limit), offset=int(offset))
    pages = courses_iterator.pages
    result = list(next(pages))
    next_url = request.base_url.split("?")
    next_url = next_url[0]
    for course in result:
        course["id"] = course.key.id
        course["self"] = next_url + "/" + str(course.key.id)
    course_list = dict()
    course_list["courses"] = result
    course_list["next"] = next_url + f"?limit=3&offset={str(int(offset) + 3)}"
    return (course_list, 200)


@app.route('/' + COURSES + '/<int:id>', methods=['GET'])
def get_course(id):
    """Returns the course with the given id, or 404"""
    requested_course = get_entity_by_id(id, COURSES)
    if requested_course is None:
        return (ERROR_404, 404)
    requested_course["id"] = requested_course.key.id
    requested_course["self"] = request.base_url
    return requested_course

def update_instructors(old_instructor, new_instructor, course_id):
    """Updates the course attribute for instructors for a particular course"""
    if old_instructor == new_instructor:
        return None
    # remove course from old instructor course attribute list
    instructor = get_entity_by_id(old_instructor, USERS)
    new_course_list = list()
    for course in instructor["courses"]:
        if course != course_id:
            new_course_list.append(course)
    instructor["courses"] = new_course_list
    del instructor["id"]
    client.put(instructor)
    # add course to new instructor course attribute list
    instructor = get_entity_by_id(new_instructor, USERS)
    if "courses" in instructor:
        instructor["courses"].append(course_id)
        del instructor["id"]
        client.put(instructor)
    else:
        course_list = list()
        course_list.append(course_id)
        instructor["courses"] = course_list
        del instructor["id"]
        client.put(instructor)
    return None
    
@app.route('/' + COURSES + '/<int:id>', methods=['PATCH'])
def update_course(id):
    """
    Update a course with the given id. If instructor id is included and is invalid, return 400.
    If JWT is invalid, return 401. If JWT is valid but is not admin, return 403.
    """
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requesting_user = get_requesting_user(payload["sub"])
    if requesting_user["role"] != "admin":
        return (ERROR_403, 403)
    content = request.get_json()
    course = get_entity_by_id(id, COURSES)
    if course is None:
        return (ERROR_403, 403)
    if "instructor_id" in content:
        valid_request = validate_course_create_request(content, ["instructor_id"])
        if not valid_request:
            return (ERROR_400, 400)
        update_instructors(course["instructor_id"], content["instructor_id"], course["id"])
    course.update(create_post_or_update_dict(content, REQUIRED_COURSE_ATTRIBUTES, course))
    del course["id"]
    client.put(course)
    course["id"] = course.key.id
    course["self"] = request.base_url
    return (course, 200)


@app.route('/' + COURSES + '/<int:id>', methods=['DELETE'])
def delete_course(id):
    """
    Delete a course with the given id. If instructor id is included and is invalid, return 400.
    If JWT is invalid, return 401. If JWT is valid but is not admin, return 403.
    """
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requesting_user = get_requesting_user(payload["sub"])
    if requesting_user["role"] != "admin":
        return (ERROR_403, 403)
    course = get_entity_by_id(id, COURSES)
    if course is None:
        return (ERROR_403, 403)
    delete_course_from_course_list(id, True, True)
    course_id_key = client.key(COURSES, course.key.id)
    client.delete(course_id_key)
    return ('', 204)


def delete_course_from_course_list(course_id, students=False, instructors=False):
    """Deletes a course from course list of students and instructors"""
    datastore_query = client.query(kind=USERS)
    datastore_query_results = datastore_query.fetch()
    for user in datastore_query_results:
        if user["role"] == "admin":
            continue
        if not students:
            continue
        if not instructors:
            continue
        if "courses" not in user:
            continue
        new_course_list = list()
        for course in user["courses"]:
            if course != course_id:
                new_course_list.append(course)
        user["courses"] = new_course_list
        client.put(user)
    return None

@app.route('/' + COURSES + '/<int:id>' + "/students", methods=['PATCH'])
def update_course_enrollment(id):
    """
    Updates the enrollment for a course based on the given 'add' or 'remove' lists in the request.
    If  JWT is invalid or missing, 401 is returned. If JWT is valid, but doesn't belong to admin
    or appropriate instructor, 403 is returned. If there are any errors in the request body, 409 is returned.
    """
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requesting_user = get_requesting_user(payload["sub"])
    # check if user is instructor, and if they are the instructor of the course
    is_teacher = False
    if "courses" in requesting_user:
        for course in requesting_user["courses"]:
            if requesting_user["role"]!= "instructor":
                break
            if course == id:
                is_teacher = True
    if requesting_user["role"] != "admin" and not is_teacher:
        return (ERROR_403, 403)
    course = get_entity_by_id(id, COURSES)
    if course is None:
        return (ERROR_403, 403)
    # verify request, check if request should return 409
    content = request.get_json()
    valid_request = verify_enrollment_list(content)
    if not valid_request:
        return {"Error": "Enrollment data is invalid"}
    # add students to course
    for student_id in content["add"]:
        student = get_entity_by_id(student_id, USERS)
        del student["id"]
        if "courses" not in student:
            student["courses"] = list()
        if id in student["courses"]:
            continue
        student["courses"].append(id)
        client.put(student)
    # remove students from course
    for student_id in content["remove"]:
        student = get_entity_by_id(student_id, USERS)
        if "courses" in student and id not in student["courses"]:
            continue
        new_course_list = list()
        for course in student["courses"]:
            if course != id:
                new_course_list.append(course)
        student["courses"] = new_course_list
        del student["id"]
        client.put(student)
    return ('', 200)


def verify_enrollment_list(request_json):
    """
    Verifies that the request body sent for updating course enrollment is valid. Returns True if so else False
    """
    # verify there are no repeats in either 'add' or 'remove'
    for student_id in request_json["add"]:
        if student_id in request_json["remove"]:
            return False
    # verify that all student_ids are valid
    add_remove_list = request_json["add"] + request_json["remove"]
    for student_id in add_remove_list:
        student = get_entity_by_id(student_id, USERS)
        if student is None:
            return False
        if student["role"] != "student":
            return False
    return True


@app.route('/' + COURSES + '/<int:id>' + "/students", methods=['GET'])
def get_enrollment(id):
    """
    Returns all students enrolled in given course id as a list. Returns 401 if JWT is invalid.
    Returns 403 if either the course doesnt exist, or the requester is not admin or the instructor
    of the course
    """
    try:
        payload = verify_jwt(request)
    except:
        return (ERROR_401, 401)
    requesting_user = get_requesting_user(payload["sub"])
    # check if user is instructor, and if they are the instructor of the course
    is_teacher = False
    if "courses" in requesting_user:
        for course in requesting_user["courses"]:
            if requesting_user["role"]!= "instructor":
                break
            if course == id:
                is_teacher = True
    if requesting_user["role"] != "admin" and not is_teacher:
        return (ERROR_403, 403)
    course = get_entity_by_id(id, COURSES)
    if course is None:
        return (ERROR_403, 403)
    response_list = list()
    all_student_list = get_query_list_where_a_equals_b("role", "student", USERS)
    for student in all_student_list:
        if "courses" in student:
            for course in student["courses"]:
                if course == id:
                    response_list.append(student)
    return (response_list, 200)
        

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

