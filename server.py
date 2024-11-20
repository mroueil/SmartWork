from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import sqlite3
import bcrypt
import logging
import os

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = 'PrPWiQ6gYy'  # Remplacez par une clé secrète unique

# Fonction pour se connecter à la base de données


def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), 'users.db')  # Utiliser un chemin absolu
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        logging.debug("Database connection established.")
        return conn
    except sqlite3.OperationalError as e:
        logging.error("Database connection failed: %s", e)
        raise
# Route pour la page d'accueil qui redirige vers la page de connexion
@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirige vers la route de connexion

# Route pour rediriger /login vers login.html
@app.route('/login')
def login():
    return redirect('/login.html')  # Redirige vers login.html

# Route pour rendre login.html
@app.route('/login.html')
def login_html():
    return render_template('login.html')  # Rendre le fichier login.html

@app.route('/add_user', methods=['POST'])
def add_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username and password:
        # Hachage du mot de passe
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Connexion à la base de données
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password.decode('utf-8')))
            conn.commit()
            return jsonify({"success": True, "message": "Utilisateur ajouté avec succès."})
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "message": "Le nom d'utilisateur existe déjà."})
        finally:
            conn.close()
    else:
        return jsonify({"success": False, "message": "Nom d'utilisateur et mot de passe requis."})

# Route pour gérer la connexion
@app.route('/login', methods=['POST'])
def handle_login():
    username = request.form.get('username')
    password = request.form.get('password')

    # Connexion à la base de données
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    # Vérifiez si l'utilisateur existe et si le mot de passe est correct
    if user:
        hashed_password = user['password']
        if isinstance(hashed_password, str):
            hashed_password = hashed_password.encode('utf-8')

        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return jsonify({"success": True})

    return jsonify({"success": False, "message": "Nom d'utilisateur ou mot de passe incorrect."})

# Route pour la page d'accueil
@app.route('/index.html')
def index():
    return render_template('index.html')  # Assurez-vous que le fichier est dans le dossier templates

# Route pour rendre admin.html
@app.route('/admin.html')
def admin_html():
    return render_template('admin.html')  # Rendre le fichier admin.html

@app.route('/Consignes.html')
def consignes():
    return render_template('Consignes.html')

@app.route('/Generateur.html')
def generateur():
    return render_template('Generateur.html')

@app.route('/Groupes.html')
def groupes():
    return render_template('Groupes.html')

@app.route('/Halloween.html')
def halloween():
    return render_template('Halloween.html')

@app.route('/Helios.html')
def helios():
    return render_template('Helios.html')

@app.route('/Template.html')
def template():
    return render_template('Template.html')

@app.route('/logout')
def logout():
    session.pop('username', None)  # Supprime le nom d'utilisateur de la session
    return redirect(url_for('login'))  # Redirige vers la page de connexion

# Route pour récupérer les utilisateurs
@app.route('/api/users')
def get_users():
    conn = get_db_connection()
    users = conn.execute('SELECT username, password FROM users').fetchall()
    conn.close()
    
    return jsonify([{"username": user["username"]} for user in users])  # Exclure le mot de passe

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    username = data.get('username')
    new_password = data.get('new_password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if user:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        conn.execute('UPDATE users SET password = ? WHERE username = ?', (hashed_password, username))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "message": "Mot de passe réinitialisé avec succès."})
    else:
        conn.close()
        return jsonify({"success": False, "message": "Utilisateur non trouvé."})

@app.route('/delete_user/<username>', methods=['DELETE'])
def delete_user(username):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        return jsonify({"success": True, "message": "Utilisateur supprimé avec succès."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
    finally:
        conn.close()


@app.route('/get_username')
def get_username():
    username = session.get('username')  # Récupérer le nom d'utilisateur de la session
    return jsonify({"username": username})  # Retourner le nom d'utilisateur en JSON

if __name__ == '__main__':
    app.run(debug=True)