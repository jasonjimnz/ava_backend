import datetime
from _sha256 import sha256
from uuid import uuid4

from neo4j.exceptions import ConstraintError
from neo4j.v1 import GraphDatabase, basic_auth


class Neo4JMixin:
    CONSTRAINT_QUERY = "CREATE CONSTRAINT ON ({prefix}:{node}) ASSERT {prefix}.{property} IS UNIQUE"
    CONSTRAINTS = [
        {'prefix': 'u', 'node': 'User', 'property': 'email'},
        {'prefix': 'r', 'node': 'Role', 'property': 'name'},
        {'prefix': 're', 'node': 'Request', 'property': 'request_id'},
        {'prefix': 'c', 'node': 'Commerce', 'property': 'commerce_id'},
        {'prefix': 's', 'node': 'Session', 'property': 'session_token'},
        {'prefix': 'p', 'node': 'Pin', 'property': 'pin_token'}
    ]
    USER_QUERY = """CREATE (u:User{{
        email: "{email}",
        password: "{password}",
        role: "{role}"
    }})"""
    SESSION_QUERY = """MATCH (u:User) WHERE id(u) = {user_id}
    WITH u
    CREATE (s:Session{{
        session_token: "{token}",
        validity: {validity},
        created_at: "{created_at}"
    }}) WITH u, s MERGE (s)-[r:SESSION_OF]->(u)
    RETURN s.session_token as token
    """
    PIN_QUERY = """
    MATCH (u:User)--(s:Session) WHERE s.session_token = "{session_token}"
    WITH u
    CREATE (p:Pin{{
        pin_token: "{token}",
        pin: {pin}
    }}) WITH u, p MERGE (p)-[r:PINCODE_OF]->(u)
    RETURN u.user_id as user_id
    """
    ROLE_QUERY = """CREATE (r:UserRole {{
        name: "{role_name}"
    }})"""
    REQUEST_QUERY = """CREATE (re:Request {{
        request_input: "{request_input}",
        created_at: "{created_at}",
        request_id: "{request_id}",
        request_lat: "{lat}",
        request_lon: "{lon}"
    }})"""
    RATING_QUERY = """CREATE (ra:Rating {{
        rated_at: "{rated_at}",
        rating: {rating}
    }})"""
    COMMERCE_QUERY = """CREATE (c:Commerce {{
        commerce_id: "{commerce_id}",
        commerce_name: "{name}",
        commerce_lat: "{lat}",
        commerce_lon: "{lon}",
        commerce_address: "{address}",
        commerce_province: "{province}",
        commerce_category: "{category}"
    }})"""

    def add_session(self, token, user_id, validity=0):
        return self.SESSION_QUERY.format(
            token=token,
            user_id=user_id,
            validity=validity,
            created_at=datetime.datetime.now().isoformat()
        )

    def add_user(self, email, password, role):
        return self.USER_QUERY.format(
            email=email,
            password=sha256(password.encode('utf-8')).hexdigest(),
            role=role
        )

    def login_user(self, email, password):
        return """MATCH (u:User) 
        WHERE u.email = "{email}" AND u.password = "{password}" 
        RETURN u.email as email, id(u) as user_id""".format(
            email=email,
            password=sha256(password.encode('utf-8')).hexdigest()
        )

    def add_pin_code(self, token, pin):
        return self.PIN_QUERY.format(session_token=token, pin=pin, token=uuid4().hex)

    def add_commerce(self, commerce_id, name, lat, lon, address, province,category):
        return self.COMMERCE_QUERY.format(
            commerce_id=commerce_id,
            name=name,
            lat=lat,
            lon=lon,
            address=address,
            province=province,
            category=category
        )

    def add_request(self, request_input, lat, lon, request_id):
        actual_date = datetime.datetime.now().isoformat()
        return self.REQUEST_QUERY.format(
            request_input=request_input,
            created_at=actual_date,
            request_id=request_id,
            lat=lat,
            lon=lon
        )


class GraphInstance(Neo4JMixin):
    driver = None
    session = None

    def __init__(self, host, port, user, password):
        self.driver = GraphDatabase.driver(
            'bolt://{host}:{port}'.format(host=host, port=port),
            auth=basic_auth(user=user, password=password)
        )
        self.session = self.create_session(self.driver)
        self.check_constraints()

    @classmethod
    def create_session(cls, driver):
        return driver.session()

    def check_constraints(self):
        for c in self.CONSTRAINTS:
            self.run_query(
                self.CONSTRAINT_QUERY.format(**c)
            )

    def run_query(self, query, debug=False, ignore_constraints=False):
        if debug:
            print("Query \n: ", query)
        if ignore_constraints:
            try:
                return self.session.run(query)
            except ConstraintError:
                return None
        else:
            return self.session.run(query)

    def register_action(self, email, password, role="user"):
        self.run_query(self.add_user(email, password, role))

    def login_action(self, email, password):
        response = self.run_query(self.login_user(email, password), debug=True)
        records = [{'email': r['email'], 'id': r['user_id']} for r in response.records()]
        if len(records) > 0:
            response2 = self.run_query(self.add_session(
                uuid4().hex,
                records[0]['id']
            ))
            records2 = [r['token'] for r in response2.records()]
            return records2
        else:
            return None

    def check_token_action(self, token):
        response = self.run_query(
            """MATCH (s:Session) 
            WHERE s.session_token = "{token}" 
            RETURN count(s) as sessions""".format(token=token)
        )
        records = [r for r in response.records()]
        if records[0]['sessions'] > 0:
            return True
        return False

    def add_pin_action(self, token, pin):
        response = self.run_query(self.add_pin_code(token, pin))
        records = [r for r in response.records()]
        if len(records) > 0:
            return True
        return False

    def check_pin_action(self, email, pin):
        response = self.run_query(
            """MATCH pa=(u:User)--(p:Pin) WHERE u.email = "{email}" AND p.pin = {pin}
            RETURN count(pa) as pins
            """.format(email=email, pin=pin)
        )
        records = [r for r in response.records()]
        if records[0]['pins'] > 0:
            return True
        return False

    def add_commerce_action(self, email, password, name,
                            lat, lon, address, province, category):
        commerce = {
            "commerce_id": uuid4().hex,
            "name": name,
            "lat": lat,
            "lon": lon,
            "address": address,
            "province": province,
            "category": category
        }
        user = {
            'email': email,
            'password': password,
            'role': 'commerce'
        }
        self.run_query(self.add_user(**user))
        self.run_query(self.add_commerce(**commerce))
        response = self.run_query("""MATCH (u:User), (c:Commerce)
        WHERE u.email = "{email}" AND c.commerce_id = "{commerce_id}"
        WITH u, c 
        MERGE (u)-[r:MANAGES]->(c) RETURN count(r) as relations
        """.format(email=email, commerce_id=commerce['commerce_id']))
        records = [r for r in response.records()]
        if records[0]['relations'] > 0:
            return True
        else:
            return False

    def add_request_action(self, token, request_input, lat, lon):
        request_id = uuid4().hex
        self.run_query(self.add_request(
            request_input=request_input,
            lat=lat,
            lon=lon,
            request_id=request_id
        ))

        response = self.run_query("""MATCH (u:User)--(s:Session), (re:Request)
        WHERE s.session_token = "{token}" AND re.request_id = "{request_id}"
        WITH u, re
        MERGE (re)-[r:REQUESTED_BY]->(u)
        RETURN count(r) as requests
        """.format(token=token, request_id=request_id))
        records = [r for r in response.records()]
        if records[0]['requests'] > 0:
            return True
        else:
            return False

    def get_near_requests_action(self, lat, lon):
        query = """
        MATCH (re:Request) 
        WITH point({{latitude:toFloat("{lat}"), longitude: toFloat("{lon}")}}) as p1,
        point({{latitude:toFloat(re.request_lat), longitude: toFloat(re.request_lon)}}) as p2, re
        RETURN re.request_id AS request_id, 
        re.created_at AS created_at, 
        re.request_lat AS request_latitude,
        re.request_lon AS request_longitude,
        re.request_input AS request_input, 
        distance(p1, p2) AS distance ORDER BY distance limit 15
        """.format(lat=lat, lon=lon)

        response = self.run_query(query)
        records = [{
            'request_id': r['request_id'],
            'created_at': r['created_at'],
            'latitude': r['request_latitude'],
            'longitude': r['request_longitude'],
            'request_content': r['request_input'],
            'distance': r['distance']
        } for r in response.records()]

        return records
