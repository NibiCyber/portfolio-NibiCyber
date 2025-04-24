import sqlite3    # 📂 Pour interagir avec une base SQLite contenant les logs d'attaques
import os         # 📁 Pour la manipulation de fichiers et chemins (sauvegardes, graphiques)
from flask import Flask, render_template    # 🌐 Pour créer une interface web locale (affichage des stats)
import matplotlib
matplotlib.use('Agg')    # 🔺 Utilise le backend non interactif de matplotlib (pas besoin d'écran pour générer les images)
import matplotlib.pyplot as plt    # 📊 Pour générer graphiques à partir des logs (pays, attaques, etc.)
from collections import Counter, defaultdict    # 💲 Compter les occurrences et structurer les données par clés
from datetime import datetime    # 🕒 Pour manipuler les horodatages dans les logs
import pytz    # 🌐 Pour gérer les fuseaux horaires (Europe/Paris)
import numpy as np    # 🔢 Pour calculs numériques (utilisé pour les histogrammes empilés)
import geoip2.database  # 🌏 Pour résoudre une IP en ASN avec GeoLite2

app = Flask(__name__)    # 🚀 Initialise l'application Flask locale (visualisation admin)

DB_FILE = "honeypot.db"    # 📂 Nom de la base de données SQLite contenant tous les logs d'attaques
STATIC_FOLDER = "static"    # 📁 Dossier contenant les images générées (graphiques)
TZ_PARIS = pytz.timezone("Europe/Paris")    # 🌏 Fuseau horaire pour afficher les dates locales
ASN_DB_PATH = "geoip/GeoLite2-ASN.mmdb"  # ← chemin vers la base GeoLite

# 🔢 Mappage de ports vers services pour les statistiques de scan
PORT_SCAN_LABELS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT",
    389: "LDAP"
}

def create_graphs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # 🌍 Récupération des pays pour générer un camembert
    cursor.execute("SELECT country FROM logs")
    countries = [row[0] for row in cursor.fetchall() if row[0]]

    def save_plot(data, title, filename, pie=False):  # 📊 Fonction utilitaire pour sauvegarder un graphique
        if not data:
            return
        counter = Counter(data)
        labels, values = zip(*counter.most_common(5))
        plt.figure(figsize=(6, 4))
        if pie:
            plt.pie(values, labels=labels, autopct='%1.1f%%')
        else:
            plt.bar(labels, values)
            plt.xticks(rotation=30)
        plt.title(title)
        plt.tight_layout()
        plt.savefig(f"{STATIC_FOLDER}/{filename}")
        plt.close()

    save_plot(countries, "Top Pays", "pays.png", pie=True)    # 🌍 Graphique camembert des pays les plus actifs

    # 🔍 User-Agent les plus fréquents
    cursor.execute("SELECT user_agent FROM logs WHERE user_agent IS NOT NULL")
    user_agents = [row[0] for row in cursor.fetchall() if row[0].strip()]
    
    if user_agents:
        counter = Counter(user_agents)
        top_agents = counter.most_common(5)
        labels = [ua[:25] + "..." if len(ua) > 28 else ua for ua, _ in top_agents]
        values = [val for _, val in top_agents]

        plt.figure(figsize=(10, 5))
        bars = plt.bar(labels, values, color="teal")
        plt.xticks(rotation=45, ha="right", fontsize=8)
        plt.ylabel("Occurrences")
        plt.title("Top User-Agent détectés")

        for bar, value in zip(bars, values):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, height + 0.5, str(value), ha='center', fontsize=9)

        plt.tight_layout()
        plt.savefig(os.path.join(STATIC_FOLDER, "user_agents.png"))
        plt.close()

    cursor.execute("SELECT ip FROM logs WHERE ip IS NOT NULL")  # 🌐 Analyse des ASN les plus fréquents
    all_ips = [row[0] for row in cursor.fetchall() if row[0]]

    asn_reader = geoip2.database.Reader(ASN_DB_PATH)
    asns = []
    for ip in all_ips:
        try:
            response = asn_reader.asn(ip)
            asn = f"AS{response.autonomous_system_number}"
            asns.append(asn)
        except:
            continue

    if asns:
        counter = Counter(asns)
        labels, values = zip(*counter.most_common(10))
        plt.figure(figsize=(10, 5))
        bars = plt.bar(labels, values, color='purple')
        plt.xticks(rotation=30)
        plt.title("ASN les plus fréquents")
        plt.ylabel("Nombre de connexions")
        for bar, val in zip(bars, values):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, str(val), ha='center')
        plt.tight_layout()
        plt.savefig(f"{STATIC_FOLDER}/top_asn.png")
        plt.close()

    cursor.execute("SELECT ip FROM logs")    # 📈 Adresses IP les plus insistantes (volume de requêtes)
    ip_counts = Counter([row[0] for row in cursor.fetchall() if row[0]])
    top_ips = ip_counts.most_common(10)
    if top_ips:
        labels, values = zip(*top_ips)
        plt.figure(figsize=(10, 5))
        bars = plt.bar(labels, values, color='crimson')
        plt.xticks(rotation=30)
        plt.ylabel("Nombre d'attaques")
        plt.title("Top IPs les plus insistantes")
        for bar, value in zip(bars, values):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, height + 0.5, str(value), ha='center', fontsize=9)
        plt.tight_layout()
        plt.savefig(f"{STATIC_FOLDER}/top_ips.png")
        plt.close()


    cursor.execute("SELECT endpoint FROM logs WHERE method='PORT_SCAN'")  # 🔌 Ports les plus scannés
    port_scans = [row[0] for row in cursor.fetchall()]
    ports = [e.replace("/port/", "") for e in port_scans if e.startswith("/port/")]
    counter = Counter(ports)

    if counter:
        labels, values = zip(*counter.items())
        plt.figure(figsize=(8, 5))
        plt.bar(labels, values, color="orange")
        plt.title("Ports les plus scannés")
        plt.ylabel("Nombre de scans")
        plt.xlabel("Port")
        plt.tight_layout()
        plt.savefig(os.path.join(STATIC_FOLDER, "port_scans.png"))
        plt.close()
        

    cursor.execute("SELECT endpoint, method, status FROM logs WHERE endpoint IS NOT NULL")     # 📊 Récupère tous les endpoints, méthodes et statuts utilisés
    rows = cursor.fetchall()

    # 🔐 Ne conserve que les pages piégées d’intérêt pour la visualisation
    valid_pages = ["/admin", "/dashboard", "/user", "/users", "/logs", "/config", "/db.backup", "/db_backup"]

    endpoint_stats = defaultdict(lambda: defaultdict(int)) # 📈 Crée une structure pour compter les appels par endpoint + méthode + statut
    for endpoint, method, status in rows:
        if endpoint in valid_pages:
            key = (endpoint, method)
            endpoint_stats[key][status] += 1

    methods = list(set([m for _, m in endpoint_stats]))   # 🔢 Récupère les méthodes HTTP uniques (ex: GET, POST)
    endpoints = sorted(set([ep for (ep, _) in endpoint_stats])) # 🔢 Trie les endpoints cibles
    x = np.arange(len(endpoints))  # → Position X pour chaque barre
    bar_bottom = np.zeros(len(endpoints))  # 🏋️ Base pour un graphique empilé

    plt.figure(figsize=(max(10, len(endpoints)), 6))  # 📈 Taille adaptée du graphique
    for method in methods:
        values = []
        for ep in endpoints:
            total = sum(endpoint_stats[(ep, method)].values())
            values.append(total)
        plt.bar(x, values, 0.6, bottom=bar_bottom, label=method)  # ▮️ Ajoute les barres pour chaque méthode empilée
        bar_bottom += values

    for i, ep in enumerate(endpoints):
        total = bar_bottom[i]
        plt.text(x[i], total + 0.5, str(int(total)), ha='center', fontsize=9, fontweight='bold') # 🔐 Affiche la valeur au-dessus de chaque barre

    plt.xticks(x, endpoints, rotation=45, ha='right')
    plt.title("Endpoints attaqués par méthode (empilé)")
    plt.xlabel("Endpoint")
    plt.ylabel("Nombre d'attaques")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(STATIC_FOLDER, "endpoints_ameliore_v2.png"))  # 📷 Sauvegarde du graphique
    plt.close()

    cursor.execute("SELECT ip, session_id, username, password, method, endpoint FROM logs")  # 🧰 Identification du type d'attaque
    rows = cursor.fetchall()

    http_sessions = defaultdict(int)
    ssh_sessions = defaultdict(int)
    for ip, session_id, username, password, method, endpoint in rows:
        if method == "POST" and endpoint == "/admin":
            http_sessions[(ip, session_id)] += 1
        elif endpoint == "/ssh":
            ssh_sessions[(ip, session_id)] += 1

    attack_types = []
    for ip, session_id, username, password, method, endpoint in rows:
        user = str(username).lower() if username else ""
        pwd = str(password).lower() if password else ""

        is_xss = any(tag in user or tag in pwd for tag in ["<script", "<img", "onerror", "alert(", "svg", "iframe"])
        is_sqli = any(x in user or x in pwd for x in ["'", "--", " or ", "1=1", "drop", "select", "union"])
        is_brute = method == "POST" and endpoint == "/admin" and http_sessions[(ip, session_id)] >= 5
        is_ssh = endpoint == "/ssh" and ssh_sessions[(ip, session_id)] >= 5
        is_ddos = http_sessions[(ip, session_id)] >= 20 or ssh_sessions[(ip, session_id)] >= 20
        is_scan = method == "PORT_SCAN"

        if is_ddos:
            attack_types.append("DDOS")
        elif is_brute:
            attack_types.append("BRUTE_FORCE_HTTP")
        elif is_ssh:
            attack_types.append("BRUTE_FORCE_SSH")
        elif is_xss:
            attack_types.append("XSS_INJECTION")
        elif is_sqli:
            attack_types.append("SQL_INJECTION")
        elif is_scan:
            attack_types.append("PORT_SCAN")
        else:
            attack_types.append("BENIGNE")  # 🔪 Requêtes sans caractère d’attaque détecté

    counter = Counter(attack_types)
    if "BENIGNE" in counter:
        del counter["BENIGNE"]

    if counter:
        labels, values = zip(*counter.items())
        plt.figure(figsize=(8, 5))
        bars = plt.bar(labels, values, color=["tomato", "gold", "skyblue", "lightgreen", "orange", "orchid"])
        for bar, value in zip(bars, values):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, height + 0.5, str(value), ha='center')

        plt.title("Types d'attaque détectés")
        plt.ylabel("Nombre de cas")
        plt.xticks(rotation=30)
        plt.tight_layout()
        plt.savefig(os.path.join(STATIC_FOLDER, "attack_type.png"))
        plt.close()

    if counter:
        labels, values = zip(*counter.items())
        plt.figure(figsize=(8, 5))
        bars = plt.bar(labels, values, color=["tomato", "gold", "skyblue", "lightgreen", "orange", "orchid"])
        for bar, value in zip(bars, values):
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2, height + 0.5, str(value), ha='center')

        plt.title("Types d'attaque détectés")
        plt.ylabel("Nombre de cas")
        plt.xticks(rotation=30)
        plt.tight_layout()
        plt.savefig(os.path.join(STATIC_FOLDER, "attack_type.png"))
        plt.close()

    conn.close()   # 🔓 Fermeture propre de la base de données

def generate_summary():
    conn = sqlite3.connect(DB_FILE)  # 🔗 Connexion à la base SQLite contenant les logs
    cursor = conn.cursor()
    summary_parts = []  # 📄 Liste qui contiendra chaque ligne du résumé dynamique

    def highlight(val):  # 🌟 Fonction interne pour mettre en valeur les données
        return f"<span class='highlight'><b>{val}</b></span>"

    # 📅 Nombre total de requêtes enregistrées
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    summary_parts.append(f"📌 Total de requêtes enregistrées : {highlight(total)}")

    # 📊 Récupère les données complètes des logs pour analyse
    cursor.execute("SELECT ip, session_id, username, password, method, endpoint FROM logs")
    rows = cursor.fetchall()

    types = Counter()  # 🔢 Pour compter chaque type d’attaque
    http_sessions = defaultdict(int)
    ssh_sessions = defaultdict(int)

# Compte les tentatives par (ip, session_id)
    for ip, session_id, username, password, method, endpoint in rows:
        if method == "POST" and endpoint == "/admin":
            http_sessions[(ip, session_id)] += 1
        elif endpoint == "/ssh":
            ssh_sessions[(ip, session_id)] += 1

    for ip, session_id, username, password, method, endpoint in rows:
        user = str(username).lower() if username else ""
        pwd = str(password).lower() if password else ""

        is_xss = any(tag in user or tag in pwd for tag in ["<script", "<img", "onerror", "alert(", "svg", "iframe"])
        is_sqli = any(x in user or x in pwd for x in ["'", "--", " or ", "1=1", "drop", "select", "union"])
        is_brute = method == "POST" and endpoint == "/admin" and http_sessions[(ip, session_id)] >= 5
        is_ssh = endpoint == "/ssh" and ssh_sessions[(ip, session_id)] >= 5
        is_ddos = http_sessions[(ip, session_id)] >= 20 or ssh_sessions[(ip, session_id)] >= 20
        is_scan = method == "PORT_SCAN"

        if is_ddos:
            types["DDOS"] += 1
        elif is_brute:
            types["BRUTE_FORCE_HTTP"] += 1
        elif is_ssh:
            types["BRUTE_FORCE_SSH"] += 1
        elif is_xss:
            types["XSS_INJECTION"] += 1
        elif is_sqli:
            types["SQL_INJECTION"] += 1
        elif is_scan:
            types["PORT_SCAN"] += 1
        else:
            types["BENIGNE"] += 1

    for atk, val in types.items():  # 🔄 Ajout des types d'attaques au résumé
        if atk != "BENIGNE":
            summary_parts.append(f"🔸 {atk} : {highlight(f'{val} requêtes')}")

    # Pays le plus actif
    cursor.execute("SELECT country FROM logs WHERE country IS NOT NULL")
    countries = [r[0] for r in cursor.fetchall()]
    if countries:
        c = Counter(countries).most_common(1)[0]
        summary_parts.append(f"🌍 Pays le plus actif : {c[0]} ({highlight(f'{c[1]} attaques')})")

    # Endpoint le plus ciblé
    cursor.execute("SELECT endpoint FROM logs WHERE endpoint IS NOT NULL")
    eps = [r[0] for r in cursor.fetchall()]
    if eps:
        e = Counter(eps).most_common(1)[0]
        summary_parts.append(f"📌 Endpoint le plus ciblé : {e[0]} ({highlight(f'{e[1]} fois')})")

    # IP la plus insistante
    cursor.execute("SELECT ip FROM logs WHERE ip IS NOT NULL")
    ips = [r[0] for r in cursor.fetchall()]
    if ips:
        ip_counter = Counter(ips)
        top_ip, top_count = ip_counter.most_common(1)[0]
        summary_parts.append(f"📍 IP la plus insistante : {top_ip} ({highlight(f'{top_count} tentatives')})")

    # ASN
    cursor.execute("SELECT ip FROM logs WHERE ip IS NOT NULL")
    asn_ips = [r[0] for r in cursor.fetchall() if r[0]]
    asn_reader = geoip2.database.Reader(ASN_DB_PATH)
    asn_list = []
    for ip in asn_ips:
        try:
            response = asn_reader.asn(ip)
            asn_number = f"AS{response.autonomous_system_number}"
            asn_list.append(asn_number)
        except:
            continue

    top_asns = Counter(asn_list).most_common(3)
    if top_asns:
        formatted_asns = ", ".join([f"{asn} ({highlight(count)})" for asn, count in top_asns])
        summary_parts.append(f"🏢 ASN les plus fréquents : {formatted_asns}")

    # Ports scannés
    cursor.execute("SELECT endpoint FROM logs WHERE method='PORT_SCAN'")
    port_endpoints = [r[0] for r in cursor.fetchall() if r[0] and r[0].startswith("/port/")]
    ports = [ep.replace("/port/", "") for ep in port_endpoints]
    top_ports = Counter(ports).most_common(3)
    if top_ports:
        formatted_ports = ", ".join([f"{port} ({highlight(count)})" for port, count in top_ports])
        summary_parts.append(f"🔌 Ports les plus scannés : {formatted_ports}")

    # User-Agent
    cursor.execute("SELECT user_agent FROM logs WHERE user_agent IS NOT NULL")
    uas = [r[0] for r in cursor.fetchall() if r[0].strip()]
    top_uas = Counter(uas).most_common(3)
    if top_uas:
        formatted_uas = ", ".join([
            f"<span class='highlight'><b>{ua[:25]}...</b></span>" if len(ua) > 28 else f"<span class='highlight'><b>{ua}</b></span>"
            for ua, _ in top_uas
        ])
        summary_parts.append(f"🧭 User-Agent les plus détectés : {formatted_uas}")

    conn.close()
    return " || ".join(summary_parts)  # 🔄 Rassemble tous les éléments sous forme de résumé dynamique HTML

@app.route("/")   # ▶️ Routes principales de l'application Flask
def visualisation():
    create_graphs()    # 📊 Génère les graphiques depuis les données de logs
    summary = generate_summary()   # 🧠 Génère un résumé statistique des attaques
    return render_template("visualisation.html", summary=summary)   # 🔁 Affiche la page visualisation

@app.route("/details")
def show_details():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")   # 🧾 Récupère tous les logs récents
    raw_logs = cursor.fetchall()

    cursor.execute("SELECT ip, session_id, COUNT(*) FROM logs GROUP BY ip, session_id")   # 📦 Compte les requêtes par session
    counts = {(ip, session_id): count for ip, session_id, count in cursor.fetchall()}

     # 🔽 Récupère les fichiers téléchargés pour chaque IP
    cursor.execute("SELECT ip, timestamp, file_name FROM downloads")
    download_entries = cursor.fetchall()

    # 🧠 Classerr les téléchargements par IP
    from collections import defaultdict
    downloads_by_ip = defaultdict(list)
    for ip_dl, ts_dl, file_name in download_entries:
        downloads_by_ip[ip_dl].append((ts_dl, file_name))

    conn.close()

    asn_reader = geoip2.database.Reader(ASN_DB_PATH)   # 🌍 Pour résolution ASN

    
    logs = []
    for row in raw_logs:
        ts_str = row[1]
        session_id = row[16] if len(row) > 16 else None
        try:
            ts_obj = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            ts_local = pytz.utc.localize(ts_obj).astimezone(TZ_PARIS)
            ts_final = ts_local.strftime("%Y-%m-%d %H:%M:%S")
        except:
            ts_final = ts_str    # 🕒 Gestion d’erreur de conversion

        ip = row[2]
        repeat = counts.get((ip, session_id), 1)   # 🔄 Nombre de répétitions de session
        google_map = f"https://www.google.com/maps/search/{row[5]}" if row[5] else ""

        username = str(row[13]).lower()
        password = str(row[14]).lower()
        endpoint = row[7]
        method = row[11]

        #print("ENDPOINT =", endpoint)  # debug

       
# ✅ Associer un fichier téléchargé uniquement si endpoint est download
        downloaded_file = "-"
        if row[7].startswith("/download_backup/"):
            file_type = row[7].split("/download_backup/")[1].split("?")[0]
            file_map = {
                "sql": "backup.sql",
                "csv": "backup.csv",
                "json": "backup.json"
            }
            downloaded_file = f"/{file_map.get(file_type, '-')}"
        elif row[7].startswith("/download_config"):
            downloaded_file = "/config.php"
        elif row[7].startswith("/download_logs"):
            downloaded_file = "/system_logs.txt"


        
        # 🔐 Comptage des attaques SSH et HTTP
        ssh_attempts = sum(1 for log in raw_logs if log[2] == ip and log[7] == "/ssh" and log[16] == session_id)
        http_attempts = sum(1 for log in raw_logs if log[2] == ip and log[7] == "/admin" and log[11] == "POST" and log[16] == session_id)
        # 🚨 Détection du type d’attaque
        is_xss = any(tag in username or tag in password for tag in ["<script", "<img", "onerror", "alert(", "svg", "iframe"])
        is_sqli = any(inj in username or inj in password for inj in ["'", "--", " or ", "1=1", "drop", "select", "union"])
        is_bruteforce = method == "POST" and endpoint == "/admin" and http_attempts >= 5
        is_ssh = endpoint == "/ssh" and ssh_attempts >= 5
        is_ddos = (http_attempts >= 20 or ssh_attempts >= 20) 
        is_scan = method == "PORT_SCAN"


        if is_scan:
            attack_type = "PORT_SCAN"
        elif is_xss:
            attack_type = "XSS_INJECTION"
        elif is_sqli:
            attack_type = "SQL_INJECTION"
        elif is_ddos:
            attack_type = "DDOS"
        elif is_ssh:
            attack_type = "BRUTE_FORCE_SSH"
        elif is_bruteforce:
            attack_type = "BRUTE_FORCE_HTTP"
        elif row[15] == "ACCESS":
            attack_type = "ACCESS"
        elif row[15] == "DOWNLOAD":
            attack_type = "DOWNLOAD"
        elif row[15] == "SUCCESS":
            attack_type = "AUTH_SUCCESS"
        elif row[15] == "FAILED":
            attack_type = "PROBE_ATTEMPT"
        else:
            attack_type = "VISIT"

        isp = row[6]
        try:
            asn_record = asn_reader.asn(ip)
            asn = f"AS{asn_record.autonomous_system_number}"
        except:
            asn = ""

        # 🧭 Détection du type de scan si PORT_SCAN
        scan_type = ""
        if attack_type == "PORT_SCAN" and endpoint.startswith("/port/"):
            try:
                scanned_port = int(endpoint.replace("/port/", ""))
                scan_type = PORT_SCAN_LABELS.get(scanned_port, "Autre")
            except:
                scan_type = "Inconnu"
        # 📋 Ajout du log structuré
        logs.append({
            "timestamp": ts_final,
            "ip": ip,
            "country": row[3],
            "region": row[4],
            "city": row[5],
            "isp": isp,
            "asn": asn,
            "endpoint": endpoint,
            "method": method,
            "user_agent": row[8],
            "username": row[13],
            "password": row[14],
            "status": row[15],
            "repeat": repeat,
            "map_url": google_map,
            "attack_type": attack_type,
            "scan_type": scan_type,
            "downloaded_file": downloaded_file,
            "session_id": session_id 
        })

    return render_template("details.html", logs=logs)  # 🎯 Affiche les logs enrichis

if __name__ == '__main__':  
    app.run(host="127.0.0.1", port=5000, debug=True)   # 🚀 Démarrage de l'application Flask en local