import argparse
import io
import sys
import logging
import zipfile
import xml.etree.ElementTree as ET
import requests
from requests.exceptions import RequestException

url_base = ""
session = requests.Session()
session.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


def login(host, username, password, auth_source=None):
    """
    Authenticates with the VCF Ops API and stores the session token.

    Args:
        host (str): The VCF Ops host.
        username (str): The username for authentication.
        password (str): The password for authentication.
        auth_source (str, optional): The authentication source. Defaults to None.

    Raises:
        SystemExit: If authentication fails or the response does not contain a token.
    """
    global url_base
    url_base = f"https://{host}/suite-api"
    logger.debug(f"Logging in to {url_base} as '{username}'")
    cred_payload = {"username": username, "password": password}
    if auth_source:
        cred_payload["authSource"] = auth_source

    response = session.post(f"{url_base}/api/auth/token/acquire", json=cred_payload)
    if response.status_code != 200:
        logger.error(f"Authentication failed: {response.status_code} {response.text}")
        sys.exit(1)

    token = response.json().get("token")
    if not token:
        logger.error("Authentication response did not contain a token")
        sys.exit(1)
    session.headers.update({"Authorization": f"vRealizeOpsToken {token}"})
    logger.info("Successfully authenticated")



def post_multipart(uri, filename, data):
    """
    Sends a multipart POST request to the VCF Ops API, uploading a file.

    Args:
        uri (str): The API endpoint URI.
        filename (str): The filename to use for the uploaded part.
        data (bytes): The file content to upload.

    Returns:
        dict | None: The JSON-decoded response, or None if the body is empty.

    Raises:
        Exception: If the request fails or returns a non-2xx status code.
    """
    logger.debug(f"POST (multipart) {uri} — file={filename}, {len(data)} bytes")
    # Use requests.post() directly (not the session) so no session-level
    # Content-Type header can override the multipart boundary that requests generates
    response = requests.post(
        f"{url_base}{uri}",
        files={"policy": (filename, data, "application/zip")},
        headers={"Authorization": session.headers.get("Authorization")},
        verify=session.verify,
    )
    logger.debug(f"POST (multipart) response: {response.status_code}")
    response.raise_for_status()
    return response.json() if response.content else None


def get(uri):
    """
    Sends a GET request to the VCF Ops API.

    Args:
        uri (str): The API endpoint URI.

    Returns:
        dict: The JSON-decoded response.

    Raises:
        Exception: If the request fails or returns a non-200 status code.
    """
    logger.debug(f"GET {uri}")
    response = session.get(f"{url_base}{uri}")
    logger.debug(f"GET response: {response.status_code}")
    response.raise_for_status()
    return response.json()


def get_raw(uri):
    """
    Sends a GET request and returns the raw response bytes.

    Args:
        uri (str): The API endpoint URI.

    Returns:
        bytes: The raw response body.

    Raises:
        Exception: If the request fails or returns a non-200 status code.
    """
    logger.debug(f"GET (raw) {uri}")
    response = session.get(f"{url_base}{uri}", headers={"Accept": "*/*"})
    logger.debug(f"GET (raw) response: {response.status_code}, {len(response.content)} bytes")
    response.raise_for_status()
    return response.content


def get_policies():
    return get("/api/policies")["policySummaries"]


def import_policy(data):
    return post_multipart("/api/policies/import?forceImport=true", "exportedPolicies.zip", data)


def export_policy(policy_id):
    return get_raw(f"/api/policies//export?id={policy_id}")


def main():
    """
    Main entry point. Fetches a named policy from VCF Ops, applies an XPath-based
    patch from a local XML file, and re-imports the modified policy.
    """
    parser = argparse.ArgumentParser(prog="policy-patcher",
                                     description="Patches a policy based on an XPath expression")
    parser.add_argument("-H", "--host", required=True, help="The address of the VCF Ops host")
    parser.add_argument("-u", "--user", required=True, help="The VCF Ops user")
    parser.add_argument("-p", "--password", required=True, help="The VCF Ops password")
    parser.add_argument("-a", "--authsource", required=False,
                        help="The VCF Ops authentication source. Default is Local")
    parser.add_argument("-n", "--name", required=True, help="The name of the policy to patch")
    parser.add_argument("-f", "--file", required=True,
                        help="Path to XML file containing the replacement XML element")
    parser.add_argument("-e", "--expression", required=False,
                        help="XPath expression to select the element to patch in the exported policy")
    parser.add_argument("-U", "--unsafe", required=False, action="store_true",
                        help="Skip certificate checking (this is unsafe!)")
    parser.add_argument("-v", "--verbose", required=False, action="store_true",
                        help="Enable verbose/debug logging")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    if args.unsafe:
        logger.debug("Certificate verification disabled (--unsafe)")
        session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    logger.debug(f"Reading replacement XML from '{args.file}'")
    with open(args.file, "r") as f:
        file_content = f.read()
    replacement_xml = ET.fromstring(file_content)
    logger.debug(f"Replacement XML root tag: <{replacement_xml.tag}>")

    try:
        login(args.host, args.user, args.password, args.authsource)
    except RequestException as e:
        if "certificate" in str(e).lower():
            logger.error(
                "The server appears to have a self-signed certificate. "
                "Override by adding the --unsafe option (not recommended in production)")
            sys.exit(1)
        raise

    logger.debug("Fetching policy list")
    policies = get_policies()
    policy = next((p for p in policies if p["name"] == args.name), None)
    if not policy:
        logger.error(f"Policy '{args.name}' not found")
        sys.exit(1)
    logger.info(f"Found policy '{args.name}' (id={policy['id']})")

    # Export the policy as a zip containing exportedPolicies.xml
    logger.debug(f"Exporting policy id={policy['id']}")
    exp = export_policy(policy["id"])
    logger.debug(f"Exported policy archive: {len(exp)} bytes")

    root = None
    with zipfile.ZipFile(io.BytesIO(exp)) as z:
        logger.debug(f"Files in exported policy archive: {[fi.filename for fi in z.infolist()]}")
        for file_info in z.infolist():
            if file_info.filename != "exportedPolicies.xml":
                continue
            logger.debug(f"Processing '{file_info.filename}'")
            with z.open(file_info) as f:
                content = f.read().decode("utf-8")
            try:
                root = ET.fromstring(content)
                matches = root.findall(args.expression)
                if not matches:
                    logger.warning(f"XPath expression '{args.expression}' matched no elements")
                else:
                    logger.info(f"XPath expression matched {len(matches)} element(s)")
                    for match in matches:
                        logger.debug(f"Before patch: {ET.tostring(match, encoding='unicode')}")
                        for child in list(match):
                            logger.debug(f"  Removing child: <{child.tag}>")
                            match.remove(child)
                        match.append(replacement_xml)
                        logger.debug(f"After patch:  {ET.tostring(match, encoding='unicode')}")
            except ET.ParseError as e:
                logger.error(f"Failed to parse exported policy as XML: {e}")
                logger.debug(f"Raw content:\n{content}")
                sys.exit(1)

    if root is None:
        logger.error("'exportedPolicies.xml' not found in exported archive")
        sys.exit(1)

    logger.debug(f"Final XML:\n{ET.tostring(root, encoding='unicode')}")

    # Build an in-memory zip with the updated XML and import it back
    updated_xml_str = ET.tostring(root, encoding="utf-8").decode("utf-8")
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zout:
        zout.writestr("exportedPolicies.xml", updated_xml_str)
    zip_bytes = zip_buffer.getvalue()
    logger.debug(f"Built in-memory zip archive: {len(zip_bytes)} bytes")

    logger.debug("Importing updated policy zip")
    import_policy(zip_bytes)

    logger.info("Policy patched successfully")


if __name__ == "__main__":
    main()
