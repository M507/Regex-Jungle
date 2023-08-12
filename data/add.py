import json, requests
ip = "127.0.0.1"
path = "/cos"


def read_json(file_name):
    # Opening JSON file
    with open(file_name, 'r') as openfile:
        # Reading from json file
        json_object = json.load(openfile)
    return json_object
 

class Collection:
    def __init__(self):
        self.api_url = "http://"+ip+":1337"

    def all(self):
        r = requests.get(self.api_url + path)
        return r.json()

    def create(self, params):
        r = requests.post(
            self.api_url + path,
            headers={"Content-Type": "application/json"},
            data=json.dumps(
                {
                    "name": params["name"],
                    "regex": params["regex"],
                }
            ),
        )
        return r.json()


c = Collection()

# r = collection.create(data)

print("Running")


json_object = read_json('output.json')

for k, v in json_object.items():
    data = {
        "name": v['name'],
        "regex": v['regex'],
    }
    r = c.create(data)
    print(v['name']+" has been added")



