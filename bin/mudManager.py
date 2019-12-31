import os

from quart import Quart, request, jsonify
from pathlib import Path

import http.client
from urllib.parse import urlparse

import logging

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
        rv = dict (self.payload or ())
        rv ['message'] = self.message
        rv ['status_code'] = self.status_code
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
    print(f"opening: {url}")
    o = urlparse(url,allow_fragments=True)
    conn = http.client.HTTPSConnection (o.netloc)
    path = o.path
    if o.query:
        path = path + '?' + o.query
    conn.request(method, path, "{}", headers)
    resp = conn.getresponse()
    print(f"Response status: {resp.status}")
    print(f"Response reason: {resp.reason}")
    resp_headers = dict(resp.getheaders())
    location = resp_headers.get('Location')
    if location:
        print(f"Redirect location: {location}")
        return request_follow_redirects(location, method, headers)
    return resp.read()

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
    url = urlparse(url_str)

    mud_data = request_follow_redirects(url.geturl(), "GET",{})
    print("MUD data:")
    print(mud_data)

    mud_filepath = mud_cache_path / ((url.netloc + url.path).replace("/","_"))
    logger.info(f"Saving MUD path {url_str} to: {mud_filepath}")
    # TODO: Save MUD body to file
    
    return "{}"

async def check_mud_signature(mud_filename, mud_sig_filename):
    # cp = subprocess.run(["openssl","smime","-verify","-in","controller.p7s","-inform","DER","-content","controller.json.badbadbad"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    pass

mud_cache_dir = os.environ.get('MUD_CACHE_DIR') or '/tmp/mud_cache_dir'
mud_cache_path = Path(mud_cache_dir)
if not mud_cache_path.exists():
    mud_cache_path.mkdir(parents=True)
if not mud_cache_path.is_dir():
    raise Exception(f"{mud_cache_dir} is not a directory")

app.run("0.0.0.0")