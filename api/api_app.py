from env_config import db_api as env_config
import requests
import re
from flask_cors import CORS
from flask import Flask, request, jsonify
import mysql.connector
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    get_jwt, unset_jwt_cookies
)
from passlib.context import CryptContext
from datetime import timedelta, datetime

app = Flask(__name__)

CORS(app)

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JWT_SECRET_KEY'] = env_config["JWT_SECRET_KEY"]

worker_access=env_config["WORKER_TOKEN"]

revoked_db_tokens = False

def get_db():
    return mysql.connector.connect(
        host=env_config["MYSQL_HOST"],
        user=env_config["MYSQL_USER"],
        password=env_config["MYSQL_PASSWORD"],
        database=env_config["MYSQL_DATABASE"],
    )
jwt = JWTManager(app)

password_process = CryptContext(
    schemes=["argon2"],
    default="argon2",
    argon2__time_cost=4,
    argon2__memory_cost=102400,
    argon2__parallelism=8,
    argon2__hash_len=32,
    argon2__salt_size=16
)

revoked_tokens = set()

def get_user_permissions(user_id):
    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("select * from nt_users_permissions where user_id = %s", (user_id,))
    return cursor.fetchone()


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in revoked_tokens

@app.route('/api/users/register', methods=['POST'])
@jwt_required()
def register():
    data = request.json
    user_data = data.get('userData')

    username = user_data.get('username')
    email = user_data.get('email')
    password = password_process.hash(user_data.get('password'))
    firstname = user_data.get('firstname')
    lastname = user_data.get('lastname')
    user_permissions = user_data.get('permissions')

    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            insert into nt_users (username, email, password, firstname, lastname)
            values (%s, %s, %s, %s, %s)
            """, (username, email, password, firstname, lastname))
        db.commit()

        user_id = cursor.lastrowid

        cursor.execute("""
            insert into nt_users_permissions (user_id, reading, admin_users, modifying)
            values (%s, %s, %s, %s)
            """, (
            user_id,
            user_permissions.get('reading'),
            user_permissions.get('admin_users'),
            user_permissions.get('modifying'),
        ))
        db.commit()
        return jsonify({'status': 'User registered'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/fetch', methods=['GET'])
@jwt_required()
def fetch_users():
    user_id = get_jwt_identity()
    permissions = get_user_permissions(user_id)

    if not permissions or not permissions['admin_users']:
        return jsonify({'error': 'Not allowed'}), 403
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            select u.user_id, u.username, u.email, u.firstname, 
            u.lastname, up.reading, up.admin_users, up.modifying
            from nt_users u join nt_users_permissions up using (user_id) order by user_id
            """)
        users = cursor.fetchall()
        #print(users)
        return jsonify(users), 200
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/remove/<int:user_id>', methods=['DELETE'])
@jwt_required()
def remove_user(user_id):
    print(user_id)
    submitting_user_id = get_jwt_identity()
    permissions = get_user_permissions(submitting_user_id)

    if not permissions or not permissions['admin_users']:
        return jsonify({'error': 'Not allowed'}), 403
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("delete from nt_users_permissions where user_id = %s", (user_id,))
        cursor.execute("delete from nt_users where user_id = %s", (user_id,))
        db.commit()
        
        return jsonify({'status': 'deleted'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/update/password/<int:user_id>', methods=['PATCH'])
@jwt_required()
def update_password(user_id):
    print(request)
    submitting_user_id = get_jwt_identity()
    permissions = get_user_permissions(submitting_user_id)

    if not permissions or not permissions['admin_users']:
        return jsonify({'error': 'Not allowed'}), 403
    
    data = request.json
    print(data)
    password = password_process.hash(data.get('new_pwd'))

    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("update nt_users set password = %s where user_id = %s", (password, user_id,))
        db.commit()
        
        return jsonify({'status': 'updated'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/update/<int:user_id>', methods=['PATCH'])
@jwt_required()
def update_users(user_id):
    submitting_user_id = get_jwt_identity()
    permissions = get_user_permissions(submitting_user_id)

    if not permissions or not permissions['admin_users']:
        return jsonify({'error': 'Not allowed'}), 403

    data = request.json
    username = data.get('username')
    firstname = data.get('firstname')
    lastname = data.get('lastname')
    email = data.get('email')
    user_permissions = data.get('permissions')

    db = get_db()
    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        update nt_users
        set username = %s, firstname = %s, lastname = %s, email = %s
        where user_id = %s
        """, (username, firstname, lastname, email, user_id))

    db.commit()

    cursor.execute("""update nt_users_permissions
        set reading = %s, admin_users = %s, modifying = %s
        where user_id = %s
        """, (
        user_permissions.get('reading'), 
        user_permissions.get('admin_users'), 
        user_permissions.get('modifying'), 
        user_id
    ))
    db.commit()
    return jsonify({'status': 'updated'}), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("select * from nt_users where username = %s", (username,))
        user = cursor.fetchone()
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    if user and password_process.verify(password, user['password']):
        access_token = create_access_token(identity=user['user_id'])
        return jsonify(token=access_token, user=user['username'], displayname=user['firstname']), 200
    
    if not user and password_process.verify(password, user['password']):
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    user_id = get_jwt_identity()
    jti = get_jwt()["jti"]
    if user_id:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("update nt_users set last_token=%s where user_id=%s", (jti, user_id))
            db.commit()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
    revoked_tokens.add(jti)
    return jsonify({"msg": "Token revoked"}), 200
    

@app.route('/api/devices/update/<int:deviceId>', methods=['PATCH'])
@jwt_required()
def update_device_meta(deviceId):
    user_id = get_jwt_identity()
    permissions = get_user_permissions(user_id)

    if not permissions or not permissions['modifying']:
        return jsonify({'error': 'Not allowed'}), 403

    data = request.json
    description = data.get('upDescription')
    extra = data.get('upExtra')
    type = data.get('type')

    try:
        if deviceId:
            deviceId = int(deviceId)
    except Exception as e:
        return jsonify({'error': 'Id not integer'}), 403

    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute("""
            update nt_devices_meta
            set description = %s, extra = %s, status = "Edited", type= %s
            where device_id = %s
            """, (description, extra, type, deviceId))
        db.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    check = data.get('orgDeviceName')
    pre_name = data.get('upDeviceName')
    name = ""
    match = re.match(r'^\(([^()]+)-\)(.+)', pre_name)
    if match: 
        prefix = match.group(1)
        inp = match.group(2)
        sp_inp = re.sub(r'[^a-zA-Z0-9._-]', '', inp)
        name = f"({prefix}-){sp_inp}"
    else: name = pre_name
    if check:
        try:
            cursor.execute("update nt_devices set name = %s where id = %s", (name, deviceId))

            db.commit()
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    
    return jsonify({'status': 'updated'}), 200

def prep_tokens():
    global revoked_db_tokens
    if revoked_db_tokens == False:
        revoked_db_tokens = True
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("""
                select last_token from nt_users;
                """)
            tokens_to_revoke = cursor.fetchall()
            for t in tokens_to_revoke:
                print(t["last_token"])
                revoked_tokens.add(t["last_token"])                  
            return jsonify({'status': 'It be done'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

with app.app_context():
    prep_tokens()

@app.route('/api/devices', methods=['GET'])
@jwt_required()
def get_devices():
    user_id = get_jwt_identity()
    permissions = get_user_permissions(user_id)
    if not permissions or not permissions['reading']:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            cursor.execute("""
                select d.name, dm.device_id, dm.ip_address 
                from nt_devices d join nt_devices_meta dm on (d.id=dm.device_id)
                """)
            devices = cursor.fetchall()
            return jsonify(devices, permissions), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500       
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("""
            select d.name, dm.device_id, dm.ip_address, dm.mac_address,
            dm.netmask, dm.gateway, dm.description, 
            dm.status, dm.lastseen, dm.extra, dm.type 
            from nt_devices d join nt_devices_meta dm on (d.id=dm.device_id)
            """)
        devices = cursor.fetchall()
        return jsonify(devices, permissions), 200
    except Exception as e:
            return jsonify({'error': str(e)}), 500      

@app.route('/api/devices/remove/<int:device_id>', methods=['DELETE'])
@jwt_required()
def remove_device(device_id):
    print(device_id)
    user_id = get_jwt_identity()
    permissions = get_user_permissions(user_id)

    if not permissions or not permissions['modifying']:
        return jsonify({'error': 'Not allowed'}), 403
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("delete from nt_devices_meta where device_id = %s", (device_id,))
        cursor.execute("delete from nt_devices where id = %s", (device_id,))
        db.commit()
        
        return jsonify({'status': 'deleted'}), 200
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500

@app.route('/api/devices/rescan', methods=['GET'])
@jwt_required()
def rescan_devices():
    user_id = get_jwt_identity()
    permissions = get_user_permissions(user_id)
    if not permissions or not permissions['modifying']:
        return jsonify({'error': 'Not allowed'}), 403
    
    headers = {
        "Authorization": worker_access
    }
    response = requests.get('http://127.0.0.1:5010/', headers=headers)
    if response.status_code == 200:
        return jsonify({"result":"Success"}), 200
    else:
        return (f"Request failed with status code {response.status_code}")
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
