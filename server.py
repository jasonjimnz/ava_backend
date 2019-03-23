from flask import Flask, jsonify, request
from flask_cors import CORS
from libs.chatbot.ava_bot import AvaBot
from libs.graph.neo_graph import GraphInstance

ava_bot = AvaBot('dialogflow_key')
neo_client = GraphInstance(
    host='localhost',
    port=7687,
    user='neo4j',
    password='neo4j'
)


app = Flask(__name__)
CORS(app)
PROJECT_VERSION = '0.0.1'


def check_client():
    pass


@app.route('/')
def home():
    return jsonify({
        'name': "Project A.V.A",
        'version': PROJECT_VERSION
    })


@app.route('/talk_to_bot', methods=['POST'])
def talk_to_bot():
    form = request.form
    result, bot_response = ava_bot.process_text(form.get('text'))
    response_dict = {
        'query': form.get('text'),
        'intent': bot_response['intent'],
        'response': bot_response['response']
    }
    print(form.get('lat'), form.get('lon'))
    if response_dict['intent'] == 'PeticionRecado':
        if form.get('token') and form.get('lat') and form.get('lon'):
            neo_client.add_request_action(
                form.get('token'),
                form.get('text'),
                form.get('lat'),
                form.get('lon')
            )
        else:
            response_dict['response'] = 'Necesitas iniciar sesión para poder pedir un recado'
    return jsonify(response_dict)


# User Endpoints
@app.route('/register', methods=['POST'])
def register_user():
    user = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    if user and password:
        if role == "commerce":
            name = request.form.get('commerce_name')
            lat = request.form.get('lat')
            lon = request.form.get('lon')
            address = request.form.get('address')
            province = request.form.get('province')
            category = request.form.get('category')
            print(name, lat, lon, address, province, category)
            if name and lat and lon and address and province and category:
                neo_client.add_commerce_action(user, password, name, lat, lon, address, province, category)
            else:
                return jsonify({
                    'mensaje': 'Faltan datos en el registro del comercio por favor revisa el formulario'
                }), 400
        else:
            neo_client.register_action(user, password, role)
        return jsonify({'mensaje': 'Te has registrado satisfactoriamente'}), 201
    return jsonify({
        'mensaje': 'Hubo un error al registrarte, revisa que hayas introducido bien el correo y la contraseña'
    }), 400


@app.route('/login', methods=['POST'])
def login_user():
    user = request.form.get('email')
    password = request.form.get('password')
    if user and password:
        res = neo_client.login_action(user, password)
        if res:
            return jsonify({'token': res[0]})
    return jsonify({
        'mensaje': 'Hubo un error al iniciar sesión, correo ó contraseña incorrectos'
    }), 401


@app.route('/check_token/<string:token>')
def check_token(token):
    token_check = neo_client.check_token_action(token)
    return jsonify({'response': token_check})


@app.route('/add_pin/<string:token>', methods=['POST'])
def add_pin(token):
    pincode = request.form.get('pin')
    if pincode:
        res = neo_client.add_pin_action(token, pincode)
        if res:
            return jsonify({'mensaje': 'El pin se ha creado correctamente'}), 201
    return jsonify({
        'mensaje': 'El código pin es necesario'
    }), 400


@app.route('/check_pin', methods=['POST'])
def check_pin():
    pincode = request.form.get('pin')
    email = request.form.get('email')
    if pincode and email:
        response = neo_client.check_pin_action(email, pincode)
        return jsonify({
            'pin': response
        })
    return jsonify({
        'mensaje': 'Hubo un error al iniciar sesión. correo ó pin incorrectos'
    })


# Petition request
@app.route('/request/order', methods=['POST'])
def request_order():
    token = request.form.get('token')
    if token:
        request_input = request.form.get('message')
        lat = request.form.get('lat')
        lon = request.form.get('lon')
        if request_input and lat and lon:
            response = neo_client.add_request_action(token, request_input, lat, lon)
            return jsonify({
                'creado': response
            })
        return jsonify({
            'mensaje': 'Hubo un error, es necesario el contenido de la petición para poder registrarla'
        })
    return jsonify({
        'mensaje': 'Vaya, parece que hubo un error con la sesión'
    }), 401


@app.route('/request/list', methods=['POST'])
def request_list():
    token = request.form.get('token')
    if token:
        lat = request.form.get('lat')
        lon = request.form.get('lon')
        if lat and lon:
            response = neo_client.get_near_requests_action(lat, lon)
            return jsonify({
                'requests': response
            })
        else:
            return jsonify({
                'mensaje': 'Hubo un error, es necesario la latitud y la longitud'
            }), 400
    else:
        return jsonify({
            'mensaje': 'Vaya parece que hubo un error con la sesión'
        }), 401


# Do request
@app.route('/request/<string:request_id>/do', methods=['POST'])
def do_request(request_id):
    token = request.form.get('token')
    if (token):
        r = neo_client.run_query("""
        MATCH (u:User)--(s:Session), (r:Request) 
        WHERE s.session_token = "{token}" 
        AND r.request_id = "{request_id}"
        WITH u, r
        MERGE (r)-[r1:REQUEST_ACCEPTED_BY]->(u) RETURN count(r1)
        """.format(token=token, request_id=request_id))
    return jsonify({
        'mensaje': 'Necesitas sesión para poder realizar un recado'
    })


app.run(host='0.0.0.0', port=5000, debug=True)
