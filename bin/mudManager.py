import os, subprocess, logging, http.client, json

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
    mud_url_str = check_field(post_data, 'url', str, True)
    version = check_field(post_data, 'version', str, True)

    mud_data = getMUDFile(mud_url_str)
    mud_json = json.loads(mud_data)
    logger.debug(f"mud_json: ")
    logger.debug(json.dumps(mud_json, indent=4))

    acls = getACLs(version, mud_json)
    logger.info(f"acls: {acls}")

    return json.dumps(acls, indent=4)

def getMUDFile(mud_url_str):
    logger.info (f"getMUDFile: url: {mud_url_str}")
    mud_url = urlparse(mud_url_str)

    mud_data_response = request_follow_redirects(mud_url.geturl(), "GET",{})
    if mud_data_response.status != 200:
        logger.info(f"Could not retrieve MUD URL {mud_url} - bailing out")
        raise InvalidUsage (400, message=f"Could not retrieve MUD URL {mud_url} (received status code {mud_data_response.status})")

    mud_data = mud_data_response.read()
    # print("MUD data: {mud_data}")

    mud_filepath = mud_cache_path / ((mud_url.netloc + mud_url.path).replace("/","_"))
    logger.info(f"Saving MUD from {mud_url_str} to {mud_filepath}...")
    
    with mud_filepath.open ('wb') as mudfile:
        mudfile.write(mud_data)

    logger.info(f"Saved MUD {mud_url_str} to {mud_filepath}")
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
            raise InvalidUsage (400, message=f"{mud_url_str} failed signature validation (via {mudsig_url_str})")

    return mud_data    

def getACLs(version, mudObj):
    #
    # Parse the JSON MUD file to extract Match rules"
    #

    # the name of from-device-policy
    fromDevicePolicyName=mudObj["ietf-mud:mud"]["from-device-policy"]\
                               ["access-lists"]["access-list"][0]["name"]

    # the name of to-device-policy 
    toDevicePolicyName=mudObj["ietf-mud:mud"]["to-device-policy"]\
                             ["access-lists"]["access-list"][0]["name"]
 
    #
    # In the case there are multiple access-lists for each direction
    #
    # num = len(outBoundACLs)
    # for item in range(num):
    #     print(outBoundACLs[item]["name"])

    # num = len(inBoundACLs)
    # for item in range(num):
    #    print(inBoundACLs[item]["name"])

    # Actual ACLs
    if fromDevicePolicyName == \
            mudObj["ietf-access-control-list:acls"]["acl"][0]["name"]: 
        fromDeviceACL= \
            mudObj["ietf-access-control-list:acls"]["acl"][0]["aces"]["ace"]
        toDeviceACL= \
            mudObj["ietf-access-control-list:acls"]["acl"][1]["aces"]["ace"]
    else:
        fromDeviceACL= \
            mudObj["ietf-access-control-list:acls"]["acl"][1]["aces"]["ace"]
        toDeviceACL= \
            mudObj["ietf-access-control-list:acls"]["acl"][0]["aces"]["ace"]
    
    # aclData= '{"acls": [{"sip": "10.10.1.1", "dip": "0.0.0.0", "sport": 0, "dport":"80","action": "accept" }]}' 

    flowRules = {}

    if version == "1.0":
        flowRules= {"acls": []}
    elif version == "1.1":
        flowRules = {"device": {"deviceId": "", "macAddress": {"eui48": ""}, "networkAddress": {"ipv4": ""},  "allowHosts": [], "denyHosts": [] } }

    #
    # Obtain fromDeviceACL
    #
    num = len(fromDeviceACL)
    logger.info(f"fromDeviceACL: {fromDeviceACL}")
    # logger.info(f"fromDeviceACL {fromDeviceACL['name']} has {num} elements")
    for i in range(num):
        dip = None
        logger.info(f"Looking at fromDeviceACL: {fromDeviceACL[i]}" )
        if "ietf-mud:mud" in fromDeviceACL[i]["matches"]:
            mud_match = fromDeviceACL[i]['matches']['ietf-mud:mud']
            logger.info(f"Found ietf-mud:mud: {mud_match}" )
            (aclMudExtension, aclMudExtensionParam) = list(mud_match.items())[0]
            
            # For all the no-param acl extensions, just use the extension name as the dest IP
            #  (with an optional param, colon-separated
            if "local-networks" in aclMudExtension \
                or "same-manufacturer" in aclMudExtension \
                or "my-controller" in aclMudExtension:
                dip = aclMudExtension
            elif "model" in aclMudExtension \
                or "manufacturer" in aclMudExtension \
                or "controller" in aclMudExtension:
                aclMudExtensionParam = list(mud_match.values())[0]
                print(f"fromDeviceACL:   found MUD extension param: {aclMudExtensionParam}")
                dip = aclMudExtension + ":" + aclMudExtensionParam
        if "ipv4" in fromDeviceACL[i]["matches"] and \
                "ietf-acldns:dst-dnsname" in fromDeviceACL[i]["matches"]["ipv4"]: 
            dip = fromDeviceACL[i]["matches"]["ipv4"]["ietf-acldns:dst-dnsname"]
        print(f"fromDeviceACL:   dip: {dip}")

        sport = 0
        if "tcp" in fromDeviceACL[i]["matches"] and \
                "source-port" in fromDeviceACL[i]["matches"]["tcp"]: 
            sport = fromDeviceACL[i]["matches"]["tcp"]["source-port"]["port"]

        dport = 0
        if "tcp" in fromDeviceACL[i]["matches"] and \
                "destination-port" in fromDeviceACL[i]["matches"]["tcp"]: 
            dport = fromDeviceACL[i]["matches"]["tcp"]["destination-port"]["port"]

        action = fromDeviceACL[i]["actions"]["forwarding"]
        # print "fromDeviceACL:   action " + action

        if version == "1.0": 
            flowRules["acls"].append({"dip":dip, \
                                  "sport": sport, "dport":dport, \
                                  "action": action}) 
        elif version == "1.1": 
            if action == "accept" and dip != None : 
                flowRules["device"]["allowHosts"].append(dip)
            elif action == "reject": 
                flowRules["device"]["denyHosts"].append(dip)

    return flowRules

mud_cache_dir = os.environ.get('MUD_CACHE_DIR') or '/tmp/mud_cache_dir'
mud_cache_path = Path(mud_cache_dir)
if not mud_cache_path.exists():
    mud_cache_path.mkdir(parents=True)
if not mud_cache_path.is_dir():
    raise Exception(f"{mud_cache_dir} is not a directory")

app.run("0.0.0.0")