import requests, json, os, uuid, tomlkit

try:
    api_key: str = os.environ["ELASTIC_API_KEY"]
except:
    api_key = "<encoded>"

try:
    api_key: str = os.environ["api_key"]
except:
    api_key = "<encoded>"

try:
    kibana_host: str = os.environ["KIBANA_HOST"]
except:
    kibana_host = "<kibana_host>"

try:
    kibana_host: str = os.environ["kibana_host"]
except:
    kibana_host = "<kibana_host>"

try:
    if "AWS_SECRET" in os.environ:
        aws_secret_dict: dict = json.loads(os.environ["AWS_SECRET"])
        print("Successfully found AWS SECRET in Environment")

    kibana_host = aws_secret_dict["kibana_host"]
    api_key = aws_secret_dict["api_key"]
except:
    pass


headers: dict = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

CWD = os.getcwd()

dr_2_elevate: list = []
with open(os.path.join(CWD,"running","rules_to_elevate.txt")) as file:
    for line in file.readlines():
        dr_2_elevate.append(line.strip())

dr_json: list = []
for dr in dr_2_elevate:
    if str(dr).endswith(".toml"):
        with open(dr, "r") as file:
            tomldoc = tomlkit.load(file)
            dr_json.append(dict(tomldoc))
    elif str(dr).endswith(".json"):
        with open(dr, "r") as file:
            temp_dr: dict = json.load(file)
            dr_json.append(temp_dr)

print("Rules to Update: {}".format(len(dr_json)))

for dr in dr_json:
    rule_id = dr["rule_id"]
    space_id = ""

    if "metadata" in dr.keys() and "space_id" in dr["metadata"].keys() and isinstance(dr["metadata"]["space_id"], str) and len(dr["metadata"]["space_id"]) > 1:
        space_id = "".join(["/s/", dr["metadata"]["space_id"]])

    with requests.Session() as session:
        r = session.put(url="https://{}{}/api/detection_engine/rules?rule_id={}".format(kibana_host, space_id, rule_id),
                        headers=headers, json=dr)
        
        print(dr["name"] + " -- '" + dr["type"] + "' -- PUT -- " + str(r.status_code))

    if r.status_code == 404:
        with requests.Session() as session:
            r = session.post(url="https://{}{}/api/detection_engine/rules?rule_id={}".format(kibana_host, space_id, rule_id),
                            headers=headers, json=dr)
            
            print(dr["name"] + " -- '" + dr["type"] + "' -- POST -- " + str(r.status_code))

    assert r.status_code >= 200 and r.status_code < 300, "A rule has failed to be created: \n{}".format(r.content)