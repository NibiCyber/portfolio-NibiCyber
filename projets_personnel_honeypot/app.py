import sqlite3       # 📦 Module standard pour interagir avec une base de données SQLite (lecture/écriture des logs)
import requests      # 🌐 Permet d’envoyer des requêtes HTTP, ici pour interroger une API de géolocalisation d’IP
import hashlib       # 🔐 Fournit des fonctions de hachage (ici utilisé pour anonymiser les User-Agent)
import datetime      # 🕒 Pour générer des timestamps (date/heure) lors des événements d’attaque
from flask import Flask, request, render_template, jsonify, redirect, url_for, Response, send_file   # 🧪 Framework web léger utilisé pour simuler les pages du honeypot, recevoir les requêtes et générer les réponses HTML ou fichiers
import os            # 📁 Module pour gérer les fichiers et chemins (création de dossiers, lecture de fichiers, etc.)
from flask_limiter import Limiter       # 🚫 Permet de limiter le nombre de requêtes d’un client (anti-flood ou brute force)
from flask_limiter.util import get_remote_address    # 🔍 Utilisé pour identifier l’adresse IP d’un client à limiter
import matplotlib                  # 📊 Bibliothèque de graphes utilisée sans interface graphique (backend 'Agg')
matplotlib.use('Agg')              # 🎨 Force l'utilisation d'un moteur de rendu adapté aux serveurs (sans interface graphique)
import matplotlib.pyplot as plt    # 📈 Outils de création de graphiques (camemberts, barres, etc.)
from collections import Counter    # 📊 Structure permettant de compter rapidement les occurrences (IP, attaques, endpoints, etc.)

# 🚀 Initialisation de l'application Flask
app = Flask(__name__)

# 📁 Chemins des dossiers et fichiers utilisés
DB_FILE = "honeypot.db"
BACKUP_FOLDER = "backups"
STATIC_FOLDER = "static"

# Initialisation de la base de données
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            isp TEXT,
            endpoint TEXT,
            user_agent TEXT,
            user_agent_hash TEXT,
            referer TEXT,
            method TEXT,
            params TEXT,
            username TEXT,
            password TEXT,
            status TEXT,
            session_id TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            file_name TEXT,
            user_agent TEXT
        )
    ''')
    conn.commit()
    conn.close()

# 📦 Création des dossiers s'ils n'existent pas
if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)
if not os.path.exists(STATIC_FOLDER):
    os.makedirs(STATIC_FOLDER)

# 🔁 Initialiser la base au lancement
init_db()

#limiter = Limiter(get_remote_address, app=app, default_limits=["15 per minute"])

# 💬 Fonction utilitaire : obtenir le timestamp actuel
def get_current_timestamp():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# 🌍 Fonction utilitaire : obtenir les infos géographiques d'une IP
def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp")
        data = response.json()
        return data.get("country"), data.get("regionName"), data.get("city"), data.get("isp")
    except:
        return None, None, None, None

# 🧾 Fonction pour logguer une tentative d’accès ou d’attaque
def log_attempt(ip, endpoint, user_agent, method, params, referer, username=None, password=None, status="FAILED", session_id=None):
    timestamp = get_current_timestamp()
    user_agent_hash = hashlib.md5(user_agent.encode()).hexdigest()
    country, region, city, isp = get_ip_info(ip)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (timestamp, ip, country, region, city, isp, endpoint, user_agent, user_agent_hash, referer, method, params, username, password, status, session_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, ip, country, region, city, isp, endpoint, user_agent, user_agent_hash, referer, method, params, username, password, status, session_id ))
    conn.commit()
    conn.close()

# 💾 Fonction pour logguer un téléchargement simulé
def log_download(ip, file_name, user_agent):
    timestamp = get_current_timestamp()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO downloads (timestamp, ip, file_name, user_agent)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, ip, file_name, user_agent))
    conn.commit()
    conn.close()

# 📍 Route racine → redirige vers /admin
@app.route('/')
def home():
    return redirect(url_for('fake_admin'))

# 🔐 Simulation d’une fausse page de connexion à /admin
@app.route('/admin', methods=['GET', 'POST'])
#@limiter.limit("10 per minute")
def fake_admin():
    ip = request.remote_addr
    method = request.method
    user_agent = request.headers.get('User-Agent', 'Unknown')

    session_id = request.form.get('session_id') or request.args.get('session_id') or None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        status = "SUCCESS" if username == "admin" and password == "test" else "FAILED"
        log_attempt(ip, "/admin", user_agent, method, str(request.form),
                    request.headers.get('Referer', 'Unknown'),
                    username, password, status, session_id=session_id)
        if status == "SUCCESS":
            return redirect(url_for('dashboard'))
    else:
        log_attempt(ip, "/admin", user_agent, method, str(request.args),
                    request.headers.get('Referer', 'Unknown'),
                    session_id=session_id)

    return render_template('login.html')

# 🖥 Fausse API SSH → capture des identifiants soumis en POST
@app.route("/ssh", methods=["POST"])
def fake_ssh():
    ip = request.remote_addr
    method = request.method
    user_agent = request.headers.get("User-Agent", "Unknown")
    session_id = request.form.get("session_id")
    username = request.form.get("username")
    password = request.form.get("password")

    print(f"[DEBUG] /ssh => session_id = {session_id}, username = {username}, password = {password}") 

    log_attempt(ip, "/ssh", user_agent, method, str(request.form), request.headers.get("Referer", "Unknown"),
                username=username, password=password, status="FAILED", session_id=session_id)
    return "SSH honeypot received.", 200

# 📊 Simulation d’un tableau de bord
@app.route('/dashboard')
def dashboard():
    ip = request.remote_addr
    log_attempt(ip, "/dashboard", request.headers.get('User-Agent', 'Unknown'), "GET", "", request.headers.get('Referer', 'Unknown'), status="ACCESS", session_id=None)
    return render_template('dashboard.html')

# 🗂 Page backup de base de données
@app.route('/db_backup')
def db_backup_page():
    ip = request.remote_addr
    log_attempt(ip, "/db_backup", request.headers.get('User-Agent', 'Unknown'), "GET", "", request.headers.get('Referer', 'Unknown'), status="ACCESS", session_id=None)
    return render_template('db_backup.html')

# 👥 Page utilisateurs
@app.route('/users')
def users():
    ip = request.remote_addr
    log_attempt(ip, "/users", request.headers.get('User-Agent', 'Unknown'), "GET", "", request.headers.get('Referer', 'Unknown'), status="ACCESS", session_id=None)
    return render_template('users.html')

# 📄 Faux logs système
@app.route('/logs')
def logs():
    ip = request.remote_addr
    log_attempt(ip, "/logs", request.headers.get('User-Agent', 'Unknown'), "GET", "", request.headers.get('Referer', 'Unknown'), status="ACCESS", session_id=None)
    return render_template('logs.html')

# ⚙️ Fausse page de configuration
@app.route('/config')
def config():
    ip = request.remote_addr
    log_attempt(ip, "/config", request.headers.get('User-Agent', 'Unknown'), "GET", "", request.headers.get('Referer', 'Unknown'), status="ACCESS", session_id=None)
    return render_template('config.html')

# 📥 Téléchargement simulé d’une sauvegarde
@app.route('/download_backup/<file_type>')
def download_backup(file_type):
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    file_map = {"sql": "backup.sql", "csv": "backup.csv", "json": "backup.json"}

    if file_type not in file_map:
        return "Type de fichier non valide", 400

    file_name = file_map[file_type]
    file_path = os.path.join(BACKUP_FOLDER, file_name)

    if not os.path.exists(file_path):
        return f"Erreur : Le fichier {file_name} n'existe pas.", 404

    
    log_download(ip, file_name, user_agent)
    log_attempt(ip, request.path, user_agent, "GET", "", request.headers.get('Referer', 'Unknown'), status="DOWNLOAD", session_id=None)

    response = send_file(file_path, as_attachment=True)
    response.headers["Cache-Control"] = "no-store"
    return response

# 📥 Faux fichier config à télécharger
@app.route('/download_config')
def download_config():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    file_name = "config.php"
    file_path = os.path.join(BACKUP_FOLDER, file_name)

    if not os.path.exists(file_path):
        fake_content = """<?php
// Configuration simulée pour leurrer l'attaquant

define("DB_HOST", "localhost");
define("DB_USER", "root");
define("DB_PASS", "SuperSecret123");
define("DB_NAME", "production");

define("AWS_ACCESS_KEY", "AKIAFAKEACCESSKEY123456");
define("AWS_SECRET_KEY", "FAKESECRETKEY0987654321");

define("SECRET_KEY", "sk_live_51ABCFAKEKEYfJ3wTn2");
?>"""
        with open(file_path, "w") as f:
            f.write(fake_content)

    # ✅ LOG obligatoire pour apparaître dans les détails
    log_download(ip, file_name, user_agent)
    log_attempt(ip, request.path, user_agent, "GET", "", request.headers.get('Referer', 'Unknown'), status="DOWNLOAD", session_id=None)

    response = send_file(file_path, as_attachment=True)
    response.headers["Cache-Control"] = "no-store"
    return response

# 📥 Logs fictifs à télécharger
@app.route('/download_logs')
def download_logs():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    file_name = "system_logs.txt"
    file_path = os.path.join(BACKUP_FOLDER, file_name)

    # ✅ Créer le fichier s’il n’existe pas encore
    if not os.path.exists(file_path):
        fake_logs = """2025-03-17 18:55:33 - Échec de connexion - IP: 203.0.113.42
2025-03-18 09:14:12 - Connexion réussie - Utilisateur: admin
2025-03-18 11:22:47 - Téléchargement config.php depuis 198.51.100.23
"""
        with open(file_path, "w") as f:
            f.write(fake_logs)

    # 🔁 Log le téléchargement
    log_download(ip, file_name, user_agent)
    log_attempt(ip, request.path, user_agent, "GET", "", request.headers.get('Referer', 'Unknown'), status="DOWNLOAD", session_id=None)

    response = send_file(file_path, as_attachment=True)
    response.headers["Cache-Control"] = "no-store"
    return response

# 🚫 Limite de requêtes atteinte
@app.errorhandler(429)
def ratelimit_error(e):
    ip = request.remote_addr
    log_attempt(ip, "/admin", request.headers.get('User-Agent', 'Unknown'), "POST", "", request.headers.get('Referer', 'Unknown'), status="BANNED", session_id=None)
    return "Too many requests, slow down!", 429

# 🚀 Lancement de l’application Flask
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)