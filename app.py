from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, g
import sqlite3  
from flask_cors import CORS
from functools import wraps
import datetime
import jwt

app = Flask(__name__)
DATABASE = 'database.db'
CORS(app)

app.config['SECRET_KEY'] = "12345"

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

#============================================================================

#JWT TOKEN CHECKING DECORATOR

#============================================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            resp = make_response('', 403)
            resp.headers['HX-Redirect'] = url_for('login_page')
            return resp
            #return jsonify({'message': 'Token is missing!'}), 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            resp = make_response('', 403)
            resp.headers['HX-Redirect'] = url_for('login_page')
            return resp
            #return jsonify({'message': 'Token is invalid!'}), 403

        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    conn = get_db_connection()
    token = request.cookies.get('token')
    if not token:
        return redirect('/login')
    else:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        notes = conn.execute("SELECT * FROM notes WHERE owner_username = (?)",(data['user'],)).fetchall()
        conn.close()
        is_htmx = request.headers.get('HX-Request') is not None
        return render_template("index.html", is_htmx = is_htmx, notes = notes)

#============================================================================

#lOGIN ENDPOINT

#============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login_page():

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        user_details = conn.execute("SELECT * FROM login_details WHERE username = (?)",(username,)).fetchone()
        if user_details is None:
            return jsonify({'message' : 'User not Found'}),401
        elif(username == user_details['username'] and password == user_details['password']):
            token = jwt.encode({
                'user': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'], algorithm="HS256")

            resp = make_response(jsonify({'message': 'Logged in'}))
            resp.set_cookie('token', token, httponly=True)
            resp.headers['HX-Redirect'] = url_for('index')
            return resp
        else:
            return jsonify({'message' : 'Password does not match'}), 401
    

    is_htmx = request.headers.get('HX-Request') is not None
    return render_template("login.html", is_htmx = is_htmx)

#============================================================================

#SIGNUP ENDPOINT

#============================================================================

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():

    if request.method == 'POST':
        email = request.form['email']
        if request.form['password'] ==request.form['re_password']:
            password = request.form['password']
        else:
            return jsonify({'message': 'Passwords are not matching!'}), 403

        conn = get_db_connection()
        conn.execute('INSERT INTO login_details (username, password) VALUES (?, ?)', (email, password))
        conn.commit()
        conn.close()

        return redirect('/')

    is_htmx = request.headers.get('HX-Request') is not None
    return render_template("signup.html", is_htmx = is_htmx)

#============================================================================

#lOGOUT ENDPOINT

#============================================================================

@app.route('/logout')
@token_required
def logout():

    resp = make_response('', 204)
    resp.set_cookie('token', '', expires=0)
    resp.headers['HX-Redirect'] = url_for('login_page') 
    return resp

#==============================================================================

#Note Addition Functionality

#=============================================================================  

@app.route('/add_note', methods = ['POST', 'GET'])
@token_required
def add_note():

    if request.method == 'GET':
        is_htmx = request.headers.get('HX-Request') is not None
        return render_template('add_note.html',is_htmx = is_htmx)
    else:
        try:
            conn = get_db_connection()
            token = request.cookies.get('token')
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            username = data['user']
            conn.execute("INSERT INTO notes (owner_username, content, posted_at_time) VALUES (?, ?, ?)", (username, request.form['note'], datetime.datetime.now()))
            conn.commit()
            conn.close()
        except Exception as e:
            return jsonify({'message' : 'Error in adding note'}), 401
        else:
            resp = make_response(jsonify({'message' : 'Note inserted Successfully'}), 200)
            resp.headers['HX-Redirect'] = url_for('index')
            return resp

@app.route('/update_note', methods = ['POST', 'GET'])
@token_required
def update_note():

    conn = get_db_connection()
    
    if request.method == 'GET':
        note_id = request.args.get('note_id')
        note = conn.execute("SELECT * FROM notes WHERE note_id = (?)", (note_id)).fetchone()
        conn.close()
        return render_template('update_note.html', note=note)

    else:
        note_id = request.form.get('note_id')
        new_content = request.form['note']
        conn.execute("UPDATE notes SET content = (?), posted_at_time = (?) WHERE note_id = (?)",(new_content, datetime.datetime.now(),note_id))
        conn.commit()
        conn.close()
        resp = make_response(jsonify({'message' : 'Note updated Successfully'}), 200)
        resp.headers['HX-Redirect'] = url_for('index')
        return resp

@app.route('/delete_note', methods = ['DELETE'])
@token_required
def delete_note():
    if request.method == 'DELETE':
        conn = get_db_connection()
        note_id = request.args.get('note_id')
        conn.execute("DELETE FROM notes WHERE note_id = (?)", (note_id))
        #conn.execute("DELETE FROM notes WHERE note_id = 4")
        conn.commit()
        conn.close()
        resp = make_response(jsonify({'message' : 'Note Deleted Successfully'}), 200)
        resp.headers['HX-Redirect'] = url_for('index')
        return resp


if __name__ == '__main__':
    app.run(debug=True)
