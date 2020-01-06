import os, subprocess, logging, http.client

from quart import Quart, request, jsonify
from pathlib import Path
from urllib.parse import urlparse


logger = logging.getLogger ('micronets-mud-manager')
logging_filename=None
logging_filemode=None
logging.basicConfig (level=logging.DEBUG, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
app_dir = os.path.abspath(os.path.dirname (__file__))

app = Quart(__name__)

class InvalidUsage (Exception):
    def __init__ (self, status_code, message, payload=None):
        Exception.__init__ (self)
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict (self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['status_code'] = self.status_code
        return rv

# This installs the handler to turn the InvalidUsage exception into a response
# See: http://flask.pocoo.org/docs/1.0/patterns/apierrors/
@app.errorhandler (InvalidUsage)
def handle_invalid_usage (error):
    response = jsonify (error.to_dict())
    response.status_code = error.status_code
    logger.info(f"Returning status {response.status_code} for {request.method} request for {request.path}: {error.message}")
    return response

@app.errorhandler (500)
def error_handler_500 (exception):
    if isinstance(exception, dict):
        error_elem = dict
    else:
        error_elem = {"error": str (exception)}
    return jsonify (error_elem), 500, {'Content-Type': 'application/json'}

@app.errorhandler (400)
def error_handler_400 (exception):
    logger.info (f"Caught 400 error handing request: {exception}")
    if isinstance(exception, dict):
        error_elem = exception
    else:
        error_elem = {"error": str (exception)}
    return jsonify (error_elem), 400, {'Content-Type': 'application/json'}

@app.errorhandler (404)
def error_handler_404 (exception):
    if isinstance(exception, dict):
        error_elem = exception
    else:
        error_elem = {"error": str (exception)}
    return jsonify (error_elem), 404, {'Content-Type': 'application/json'}

def check_field (json_obj, field, field_type, required):
    if field not in json_obj:
        if required:
            raise InvalidUsage (400, message=f"Required field '{field}' missing from {json_obj}")
        else:
            return
    field_val = json_obj [field]
    if not isinstance (field_val, field_type):
        raise InvalidUsage (400, message=f"Supplied field value '{field_val}' for '{field}' field"
                                         f" in '{json_obj}' is not a {field_type}")
    return field_val

def check_for_unrecognized_entries (container, allowed_field_names):
    keys = container.keys ()
    unrecognized_keys = keys - allowed_field_names  # This is set subtraction
    if ((len (unrecognized_keys)) > 0):
        raise InvalidUsage (400, message=f"Illegal field(s) {unrecognized_keys} in '{container}'")
    return True

def request_follow_redirects(url, method, headers):
    o = urlparse(url,allow_fragments=True)
    conn = http.client.HTTPSConnection (o.netloc)
    path = o.path
    if o.query:
        path = path + '?' + o.query
    conn.request(method, path, "{}", headers)
    resp = conn.getresponse()
    resp_headers = dict(resp.getheaders())
    location = resp_headers.get('Location')
    if location:
        print(f"Redirecting to: {location}")
        return request_follow_redirects(location, method, headers)
    return resp

def file_signature_validates(filepath, sigpath):
    cp = subprocess.run(["openssl","smime","-verify","-in",str(sigpath),
                         "-inform","DER","-content",str(filepath)], 
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # logger.info(f"Signature validation command returned {cp}")
    status_msg = cp.stderr.decode("utf-8").strip()
    logger.info(f"Signature validation command returned status {cp.returncode} ({status_msg})")
    return (cp.returncode == 0, status_msg)

@app.route('/getFlowRules', methods=['POST'])
async def get_flow_rules():
    if not request.is_json:
        raise InvalidUsage (400, message="supplied data is not a valid json object")
    post_data = await request.get_json()
    logger.info (f"getFlowRules called with: {post_data}")
    print(post_data)
    check_for_unrecognized_entries(post_data,['url','version','ip'])
    url_str = check_field(post_data, 'url', str, True)
    logger.info (f"getFlowRules: url: {url_str}")
    mud_url = urlparse(url_str)

    mud_data_response = request_follow_redirects(mud_url.geturl(), "GET",{})
    if mud_data_response.status != 200:
        logger.info(f"Could not retrieve MUD URL {mud_url} - bailing out")
        raise InvalidUsage (400, message=f"Could not retrieve MUD URL {mud_url} (received status code {mud_data_response.status})")

    mud_data = mud_data_response.read()
    # print("MUD data: {mud_data}")

    mud_filepath = mud_cache_path / ((mud_url.netloc + mud_url.path).replace("/","_"))
    logger.info(f"Saving MUD from {url_str} to {mud_filepath}...")
    
    with mud_filepath.open ('wb') as mudfile:
        mudfile.write(mud_data)

    logger.info(f"Saved MUD {url_str} to {mud_filepath}")
    if mud_url.path.endswith(".json"):
        base_path = mud_url.path[0:-5]
    else:
        base_path = mud_url.path
    mudsig_url_str = mud_url.scheme+"://"+mud_url.netloc+base_path+".p7s"
    if mud_url.query:
        mudsig_url_str = mudsig_url_str + "?" + mudsig_url.query

    mudsig_url = urlparse(mudsig_url_str)
    logger.info(f"Attempting to retrieve MUD signature from {mudsig_url_str}")
    mudsig_data_response = request_follow_redirects(mudsig_url_str, "GET",{})
    if mudsig_data_response.status != 200:
        logger.info(f"Could not retrieve MUD signature URL {mudsig_url} (received status code {mudsig_data_response.status})")
    else:
        logger.info(f"Successfully retrieved {mudsig_url}")
        mudsig_data = mudsig_data_response.read()
        mudsig_filepath = mud_cache_path / ((mudsig_url.netloc + mudsig_url.path).replace("/","_"))
        logger.info(f"Saving MUD from {mudsig_url_str} to {mudsig_filepath}...")
    
        with mudsig_filepath.open ('wb') as mudsigfile:
            mudsigfile.write(mudsig_data)
        (validated, validation_msg) = file_signature_validates(mud_filepath, mudsig_filepath)
        if validated:
            logger.info(f"Successfully validated MUD file {mud_filepath} (via {mudsig_filepath})")
        else:
            raise InvalidUsage (400, message=f"{url_str} failed signature validation (via {mudsig_url_str})")

    return "{}"

mud_cache_dir = os.environ.get('MUD_CACHE_DIR') or '/tmp/mud_cache_dir'
mud_cache_path = Path(mud_cache_dir)
if not mud_cache_path.exists():
    mud_cache_path.mkdir(parents=True)
if not mud_cache_path.is_dir():
    raise Exception(f"{mud_cache_dir} is not a directory")

app.run("0.0.0.0")