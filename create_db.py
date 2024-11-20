import sqlite3
import bcrypt

# Connexion à la base de données (ou création si elle n'existe pas)
conn = sqlite3.connect('users.db')

# Création d'un curseur
cursor = conn.cursor()

# Création de la table des utilisateurs
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
''')

# Hachage du mot de passe pour l'utilisateur admin
hashed_password_admin = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())

# Insertion de l'utilisateur administrateur
cursor.execute('''
INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
''', ('admin', hashed_password_admin.decode('utf-8')))  # Stockez le mot de passe haché

# Hachage du mot de passe pour l'utilisateur à renommer
hashed_password_maison = bcrypt.hashpw('Maison2024'.encode('utf-8'), bcrypt.gensalt())

# Insertion de l'utilisateur avec le mot de passe "Maison2024"
cursor.execute('''
INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
''', ('Maison2024', hashed_password_maison.decode('utf-8')))  # Stockez le mot de passe haché

# Renommer l'utilisateur avec le nom d'utilisateur "Maison2024" en "test"
# Hachage du nouveau mot de passe pour l'utilisateur "test"
hashed_password_test = bcrypt.hashpw('Maison2024'.encode('utf-8'), bcrypt.gensalt())

# Mise à jour du nom d'utilisateur
cursor.execute('''
UPDATE users SET username = ?, password = ? WHERE username = ?
''', ('test', hashed_password_test.decode('utf-8'), 'Maison2024'))

# Sauvegarde (commit) et fermeture de la connexion
conn.commit()
conn.close()