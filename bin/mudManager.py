import os, subprocess, logging, http.client, json, ssl, argparse

from quart import Quart, request, jsonify
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime, timedelta

logger = logging.getLogger ('micronets-mud-manager')
logging_filename=None
logging_filemode=None
logging.basicConfig (level=logging.DEBUG, filename=logging_filename, filemode=logging_filemode,
                     format='%(asctime)s %(name)s: %(levelname)s %(message)s')
app_dir = os.path.abspath(os.path.dirname (__file__))

bin_path = Path (__file__).parent

arg_parser = argparse.ArgumentParser(description='A MUD Manager that generates Micronets-compatible ACLs')

arg_parser.add_argument ('--ca-certs', "-cac", required=False, action='store', type=open,
                         default = os.environ.get('MICRONETS_MUD_CA_CERT'),
                         help="add the given CA cert to the list of trusted root certs (or MICRONETS_MUD_CA_CERT)")
arg_parser.add_argument ('--ca-path', "-cap", required=False, action='store', type=str,
                         default = os.environ.get('MICRONETS_MUD_CA_PATH') or "/etc/ssl/certs",
                         help="add the given CA cert to the list of trusted root certs (or MICRONETS_MUD_CA_PATH)")
arg_parser.add_argument ('--bind-address', "-a", required=False, action='store', type=str,
                         default=os.environ.get('MICRONETS_MUD_BIND_ADDRESS') or "0.0.0.0",
                         help="specify the address to bind the MUD manager to (or MICRONETS_MUD_BIND_ADDRESS)")
arg_parser.add_argument ('--bind-port', "-p", required=False, action='store', type=int,
                         default = os.environ.get('MICRONETS_MUD_BIND_PORT') or 5000,
                         help="specify the port to bind the MUD manager to (or MICRONETS_MUD_BIND_PORT)")
arg_parser.add_argument ('--cache-dir', "-cd", required=False, action='store', type=str,
                         default = os.environ.get('MICRONETS_MUD_CACHE_DIR') or '/var/cache/micronets-mud',
                         help="add the given CA cert to the list of trusted root certs (or MICRONETS_MUD_CACHE_DIR)")

args = arg_parser.parse_args ()

logger.info(f"Bind address: {args.bind_address}")
logger.info(f"Bind port: {args.bind_port}")
logger.info(f"CA path: {args.ca_path}")
logger.info(f"Additional CA certs: {args.ca_certs.name if args.ca_certs else None}")
logger.info(f"MUD cache directory: {args.cache_dir}")

mud_cache_path = Path(args.cache_dir)
if not mud_cache_path.exists():
    mud_cache_path.mkdir(parents=True)
if not mud_cache_path.is_dir():
    raise argparse.ArgumentTypeError("The MUD cache directory ({args.cache_dir}) is not valid and cannot be created")

app = Quart(__name__)


# mud_cache_path = Path(mud_cache_dir)
# if not mud_cache_path.exists():
#     mud_cache_path.mkdir(parents=True)
# if not mud_cache_path.is_dir():
#     raise Exception(f"{mud_cache_dir} is not a directory")


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
    conn = http.client.HTTPSConnection (o.netloc, context=ssl_context)
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
    status_msg = cp.stderr.decode("utf-8")
    status_lines = status_msg.splitlines(keepends=True)
    status_msg = status_lines[0].strip()
    error_output = "".join(status_lines[1:])
    logger.debug(f"Signature validation command returned status {cp.returncode} ({status_msg})")
    return (cp.returncode == 0, status_msg, error_output)

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

    mud_json = getMUDFile(mud_url_str)
    # logger.debug(f"mud_json: ")
    # logger.debug(json.dumps(mud_json, indent=4))

    acls = getACLs(version, mud_json, post_data['ip'])
    logger.info(f"acls: {acls}")

    return json.dumps(acls, indent=4)

def getMUDFile(mud_url_str):
    logger.info (f"getMUDFile: url: {mud_url_str}")
    mud_url = urlparse(mud_url_str)
    mud_filepath = mud_cache_path / ((mud_url.netloc + mud_url.path).replace("/","_"))
    mud_md_filepath = Path(str(mud_filepath) + ".md")
    logger.info(f"getMUDFile: mud filepath for {mud_url_str}: {mud_filepath}...")

    mud_json = None
    # Check the cache and return the MUD from the cache if it hasn't expired
    if mud_filepath.exists():
        if not mud_md_filepath.exists():
            logger.warn(f"getMUDFile: FAILED loading MD file {mud_md_filepath} from CACHE - DELETING {mud_filepath}")
            mud_filepath.unlink()
        else:
            mud_md_json = json.loads(mud_md_filepath.open().read())
            cache_expiration_timestamp_str = mud_md_json["expiration-timestamp"]
            cache_expiration_timestamp = datetime.fromtimestamp(cache_expiration_timestamp_str)
            logger.debug(f"getMUDFile: {mud_md_filepath} expiration is "
                         + cache_expiration_timestamp.isoformat())
            if datetime.today() < cache_expiration_timestamp:
                logger.info(f"getMUDFile: LOADING {mud_url_str} from CACHE ({mud_filepath})")
                mud_json = json.loads(mud_filepath.open().read())
            else:
                logger.info(f"getMUDFile: EXPIRING {mud_url_str} from CACHE ({mud_filepath})")
                mud_filepath.unlink()
                mud_md_filepath.unlink()

    if not mud_json:
        # Retrieve the MUD from the origin server
        logger.info(f"getMUDFile: RETRIEVING {mud_url_str}")
        mud_data_response = request_follow_redirects(mud_url.geturl(), "GET",{})
        if mud_data_response.status != 200:
            logger.info(f"Could not retrieve MUD URL {mud_url} - bailing out")
            raise InvalidUsage (400, message=f"Could not retrieve MUD URL {mud_url} (received status code {mud_data_response.status})")

        mud_data = mud_data_response.read()
        # print("MUD data: {json.dumps(mud_json,indent=4)}")

        with mud_filepath.open ('wb') as mudfile:
            mudfile.write(mud_data)

        logger.debug(f"Saved MUD {mud_url_str} to {mud_filepath}")

        # Attempt to retrieve the MUD signature
        if mud_url.path.endswith(".json"):
            base_path = mud_url.path[0:-5]
        else:
            base_path = mud_url.path
        mudsig_url_str = mud_url.scheme+"://"+mud_url.netloc+base_path+".p7s"
        if mud_url.query:
            mudsig_url_str = mudsig_url_str + "?" + mudsig_url.query

        mudsig_url = urlparse(mudsig_url_str)
        # TODO: Check for a "mud-signature" element and use that path if/when it exists
        logger.info(f"Attempting to retrieve MUD signature from {mudsig_url_str}")
        mudsig_data_response = request_follow_redirects(mudsig_url_str, "GET",{})
        if mudsig_data_response.status != 200:
            # No MUD sig retrieved - carry on w/o validation
            logger.debug(f"Could not retrieve a MUD signature from {mudsig_url_str} (received status code {mudsig_data_response.status})")
            logger.info(f"No signature found for {mudsig_url_str} - continuing...")
        else:
            # MUD sig retrieved - now the MUD must validate with the sig (or fail)
            logger.info(f"Successfully retrieved MUD signature {mudsig_url_str}")
            mudsig_data = mudsig_data_response.read()
            mudsig_filepath = mud_cache_path / ((mudsig_url.netloc + mudsig_url.path).replace("/","_"))
            with mudsig_filepath.open('wb') as mudsigfile:
                mudsigfile.write(mudsig_data)
            logger.info(f"Saved MUD signature from {mudsig_url_str} to {mudsig_filepath}")

            (validated, validation_msg, error_msg) \
                = file_signature_validates(mud_filepath, mudsig_filepath)
            mudsig_filepath.unlink()
            if validated:
                logger.info(f"MUD signature validation SUCCESS "
                            f"(MUD file {mud_filepath}, sig file {mudsig_filepath})")
            else:
                logger.info(f"MUD signature validation FAILURE "
                            f"(MUD file {mud_filepath}, sig file {mudsig_filepath})")
                logger.info(f"Signature failure details: \n{error_msg}")
                mud_filepath.unlink()
                raise InvalidUsage (400, message=f"{mud_url_str} failed signature validation (via {mudsig_url_str}): "
                                                 + validation_msg)
        mud_json = json.loads(mud_data)

        # Save expiration time for the MUD file
        cache_validity_hours = mud_json['ietf-mud:mud']['cache-validity']
        logger.info(f"cache-validity for {mud_url_str} is {cache_validity_hours} hours")

        cache_validity_delta = timedelta(hours=cache_validity_hours)
        cache_validity_datetime = datetime.today() + cache_validity_delta
        logger.info(f"expiration for {mud_url_str} is {cache_validity_datetime.isoformat()}")

        mud_md_dict = {"expiration-timestamp": cache_validity_datetime.timestamp()}
        logger.info(f"Dict for {mud_url_str}: {mud_md_dict}")
        mud_md_json = json.dumps(mud_md_dict, indent=3) + "\n"
        mud_md_filepath.write_text(mud_md_json)
        logger.info(f"Wrote metadata for {mud_url_str}: {mud_md_json}")

    return mud_json

def getACLs(version, mudObj, devAddress):
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
        flowRules = {"device":
                         {"deviceId": "", "macAddress": {"eui48": ""},
                          "networkAddress": {"ipv4": f"{devAddress}"},
                          "allowHosts": [], "denyHosts": [] } }
    #
    # Obtain fromDeviceACL
    #
    num = len(fromDeviceACL)
    logger.info(f"fromDeviceACL: {fromDeviceACL}")
    # logger.info(f"fromDeviceACL {fromDeviceACL['name']} has {num} elements")
    for i in range(num):
        dip = None
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

ssl_context = ssl.SSLContext (ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations (cafile = args.ca_certs.name if args.ca_certs else None, capath=args.ca_path)
ssl_context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
# ssl_context.check_hostname = False

app.run(args.bind_address, args.bind_port)