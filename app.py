@app.route('/home')
def hello_world():
    user = request.args.get("user")

    input_dict = {
        "input": {
            "user": user,
            "path": "home",
        }
    }
    rsp = requests.post("http://localhost:8181/..authz", json=input_dict)

    if not rsp.json()["result"]["allow"]:
        return 'Unauthorized!', 401

    return 'Welcome Home', 200