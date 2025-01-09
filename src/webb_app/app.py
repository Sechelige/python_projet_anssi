from flask import Flask, render_template, request, redirect, url_for, flash
import smtplib
from email.mime.text import MIMEText
import json
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.utils import PlotlyJSONEncoder

# Initialisation de l'application Flask
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Remplacez par une clé secrète sécurisée

# Données initiales
DATA = {    'Titre ANSSI': [
        'Alerte : Vulnérabilité critique dans Apache',
        'Avis : Vulnérabilité dans Ivanti Policy Secure',
        'Alerte : Vulnérabilité dans Nginx',
        'Avis : Vulnérabilité dans Cisco ASA',
        'Alerte : Vulnérabilité dans Microsoft Exchange',
        'Avis : Vulnérabilité dans Fortinet FortiGate',
        'Alerte : Vulnérabilité dans OpenSSL',
        'Avis : Vulnérabilité dans VMware vSphere',
        'Alerte : Vulnérabilité dans MySQL',
        'Avis : Vulnérabilité dans Docker',
        'Alerte : Vulnérabilité dans Kubernetes',
        'Avis : Vulnérabilité dans Apache Tomcat',
        'Alerte : Vulnérabilité dans Redis',
        'Avis : Vulnérabilité dans Google Chrome',
        'Alerte : Vulnérabilité dans PostgreSQL',
        'Avis : Vulnérabilité dans Oracle WebLogic',
        'Alerte : Vulnérabilité dans Jenkins',
        'Avis : Vulnérabilité dans Wireshark',
        'Alerte : Vulnérabilité dans Samba',
        'Avis : Vulnérabilité dans GitLab'
    ],
    'Type': ['Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis', 'Alerte', 'Avis'],
    'Date': ['2024-06-01', '2024-06-05', '2024-06-10', '2024-06-12', '2024-06-15', '2024-06-17', '2024-06-20', '2024-06-22', '2024-06-25', '2024-06-30', '2024-07-01', '2024-07-05', '2024-07-07', '2024-07-10', '2024-07-12', '2024-07-15', '2024-07-18', '2024-07-20', '2024-07-22', '2024-07-23'],
    'CVE': [
        'CVE-2023-46805', 'CVE-2024-21887', 'CVE-2024-11234', 'CVE-2024-11345', 'CVE-2024-11567', 
        'CVE-2024-11678', 'CVE-2024-11987', 'CVE-2024-12012', 'CVE-2024-12123', 'CVE-2024-12234',
        'CVE-2024-12345', 'CVE-2024-12456', 'CVE-2024-12567', 'CVE-2024-12678', 'CVE-2024-12789',
        'CVE-2024-12890', 'CVE-2024-12901', 'CVE-2024-13012', 'CVE-2024-13123', 'CVE-2024-13234'
    ],
    'CVSS Base': [8.2, 9.0, 7.5, 8.5, 9.0, 8.7, 7.0, 7.8, 8.1, 7.9, 8.0, 7.6, 7.8, 8.2, 8.4, 7.9, 8.3, 8.1, 7.7, 8.0],
    'Severity': ['High', 'Critical', 'High', 'Medium', 'Critical', 'High', 'Medium', 'High', 'High', 'Medium', 'Critical', 'High', 'High', 'Medium', 'High', 'High', 'Critical', 'Medium', 'High', 'Critical'],
    'CWE': [
        'CWE-287 (Authentication Bypass)', 'CWE-77 (Command Injection)', 'CWE-78 (OS Command Injection)', 
        'CWE-119 (Buffer Overflow)', 'CWE-119 (Buffer Overflow)', 'CWE-120 (Buffer Copy without Size Checking)', 
        'CWE-79 (Improper Neutralization of Input During Web Page Generation)', 'CWE-79 (Cross-Site Scripting)', 
        'CWE-119 (Buffer Overflow)', 'CWE-77 (Command Injection)', 'CWE-79 (Cross-Site Scripting)', 
        'CWE-119 (Buffer Overflow)', 'CWE-120 (Buffer Copy without Size Checking)', 'CWE-119 (Buffer Overflow)', 
        'CWE-284 (Improper Access Control)', 'CWE-287 (Authentication Bypass)', 'CWE-119 (Buffer Overflow)', 
        'CWE-78 (OS Command Injection)', 'CWE-79 (Cross-Site Scripting)', 'CWE-120 (Buffer Copy without Size Checking)'
    ],
    'EPSS': [0.85, 0.92, 0.78, 0.65, 0.90, 0.75, 0.88, 0.77, 0.80, 0.85, 0.91, 0.70, 0.72, 0.88, 0.79, 0.90, 0.85, 0.92, 0.87, 0.75],
    'Lien': [
        'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 
        'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 
        'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 
        'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 
        'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 
        'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...', 
        'https://www.cert.ssi.gouv.fr/...', 'https://www.cert.ssi.gouv.fr/...'
    ],
    'Description': [
        'An authentication bypass vulnerability...', 'A command injection vulnerability allows execution.', 
        'Remote code execution vulnerability...', 'Memory corruption vulnerability...', 'Privilege escalation vulnerability...', 
        'Cross-site scripting vulnerability...', 'Directory traversal vulnerability...', 'SQL injection vulnerability...', 
        'Path traversal vulnerability...', 'Denial of service vulnerability...', 'Command injection vulnerability...', 
        'Improper authentication vulnerability...', 'Out-of-bounds read vulnerability...', 'Privilege escalation vulnerability...', 
        'File inclusion vulnerability...', 'Cross-site scripting vulnerability...', 'Code execution vulnerability...', 
        'Stack buffer overflow vulnerability...', 'Out-of-bounds write vulnerability...', 'Improper access control vulnerability...'
    ],
    'Éditeur': [
        'Ivanti', 'Ivanti', 'Nginx', 'Cisco', 'Microsoft', 'Fortinet', 'OpenSSL', 'VMware', 'MySQL', 'Docker', 
        'Kubernetes', 'Apache', 'Redis', 'Google', 'PostgreSQL', 'Oracle', 'Jenkins', 'Wireshark', 'Samba', 'GitLab'
    ],
    'Produit': [
        'ICS', 'IPS', 'Web Server', 'ASA', 'Exchange', 'FortiGate', 'OpenSSL', 'vSphere', 'MySQL', 'Docker', 
        'Kubernetes', 'Tomcat', 'Redis', 'Chrome', 'PostgreSQL', 'WebLogic', 'Jenkins', 'Wireshark', 'Samba', 'GitLab'
    ],
    'Versions affectées': [
        '9.1R18, 22.6R2', '9.1R18, 22.6R1', '1.18.0', '9.12', '2019-2023', '6.0', '1.1.1k', '7.0.0', '5.7', '20.10.7', 
        '1.21', '9.0.0', '6.0', '110.0', '13.3', '12.2', '2.5', '4.3', '4.3', '14.0'
    ]}
df = pd.DataFrame(DATA)

# Chemin vers le fichier JSON pour stocker les abonnés
subscribers_file = os.path.join(app.static_folder, "subscribers.json")

def load_subscribers():
    """Charge la liste des abonnés depuis un fichier JSON."""
    if os.path.exists(subscribers_file):
        with open(subscribers_file, 'r') as f:
            return json.load(f)
    return []

def save_subscribers(subscribers):
    """Sauvegarde la liste des abonnés dans un fichier JSON."""
    with open(subscribers_file, 'w') as f:
        json.dump(subscribers, f)

def send_email(to_email, subject, template_name):
    """Envoie un email HTML via SMTP.

    Args:
        to_email (str): Adresse email du destinataire.
        subject (str): Sujet de l'email.
        template_name (str): Nom du template HTML à utiliser pour le corps de l'email.
    """
    from_email = "mailing.list.alert.anssi@gmail.com"
    password = "joja qpfn chdg oiqr"  # Mot de passe d'application sécurisé

    html_body = render_template(template_name, email=to_email)
    msg = MIMEText(html_body, 'html')
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'email : {e}")

def send_alert_email(subject, body):
    """Envoie un email d'alerte à tous les abonnés."""
    subscribers = load_subscribers()
    for email in subscribers:
        send_email(email, subject, body)

def generate_charts():
    """Génère des graphiques interactifs à partir des données et les encode en JSON."""
    charts = {}

    try:
        # Histogramme des scores CVSS
        fig_cvss = px.histogram(df, x="CVSS Base", nbins=10, title="Distribution des scores CVSS",
                                labels={"CVSS Base": "Score CVSS"}, template="plotly_white")
        charts['cvss_histogram'] = json.dumps(fig_cvss, cls=PlotlyJSONEncoder)

        # Diagramme circulaire des types de vulnérabilités (CWE)
        fig_cwe = px.pie(df, names="CWE", title="Répartition des types de vulnérabilités (CWE)")
        charts['cwe_pie'] = json.dumps(fig_cwe, cls=PlotlyJSONEncoder)

        # Courbe des scores EPSS
        fig_epss = px.line(df, x=df.index, y="EPSS", title="Courbe des scores EPSS",
                           labels={"x": "Index", "EPSS": "Score EPSS"}, template="plotly_white")
        charts['epss_line'] = json.dumps(fig_epss, cls=PlotlyJSONEncoder)

        # Classement des produits les plus affectés
        product_counts = df['Produit'].value_counts().head(10)
        fig_products = px.bar(product_counts, orientation="h", title="Produits les plus affectés",
                              labels={"index": "Produit", "value": "Nombre de vulnérabilités"},
                              template="plotly_white")
        charts['products_bar'] = json.dumps(fig_products, cls=PlotlyJSONEncoder)

        # Heatmap des corrélations entre CVSS et EPSS
        corr_matrix = df[['CVSS Base', 'EPSS']].corr()
        fig_heatmap = go.Figure(data=go.Heatmap(
            z=corr_matrix.values,
            x=corr_matrix.columns,
            y=corr_matrix.index,
            colorscale="Viridis"
        ))
        fig_heatmap.update_layout(title="Corrélation entre CVSS et EPSS", template="plotly_white")
        charts['heatmap'] = json.dumps(fig_heatmap, cls=PlotlyJSONEncoder)

        # Nuage de points entre CVSS et EPSS
        fig_scatter = px.scatter(df, x="CVSS Base", y="EPSS", color="Severity", size="EPSS",
                                 title="Relation entre CVSS et EPSS",
                                 labels={"CVSS Base": "Score CVSS", "EPSS": "Score EPSS"},
                                 template="plotly_white")
        charts['scatter_plot'] = json.dumps(fig_scatter, cls=PlotlyJSONEncoder)

        # Boxplot des scores CVSS par éditeur
        fig_boxplot = px.box(df, x="Éditeur", y="CVSS Base", title="Distribution des scores CVSS par éditeur",
                             labels={"Éditeur": "Éditeur", "CVSS Base": "Score CVSS"},
                             template="plotly_white")
        charts['boxplot'] = json.dumps(fig_boxplot, cls=PlotlyJSONEncoder)

        # Évolution temporelle des vulnérabilités détectées
        df['Date'] = pd.to_datetime(df['Date'])
        vuln_per_date = df.groupby('Date').size().reset_index(name='Nombre de vulnérabilités')
        fig_time = px.line(vuln_per_date, x="Date", y="Nombre de vulnérabilités",
                           title="Évolution temporelle des vulnérabilités détectées",
                           labels={"Date": "Date", "Nombre de vulnérabilités": "Nombre"},
                           template="plotly_white")
        charts['time_series'] = json.dumps(fig_time, cls=PlotlyJSONEncoder)

    except Exception as e:
        print(f"Erreur lors de la génération des graphiques : {e}")

    return charts

@app.route("/", methods=["GET", "POST"])
def home():
    """Page d'accueil pour la gestion des abonnés."""
    if request.method == "POST":
        email = request.form.get("email")
        if email and "@" in email:
            subscribers = load_subscribers()
            if email in subscribers:
                flash("Vous êtes déjà abonné(e) à notre liste.", "danger")
            else:
                subscribers.append(email)
                save_subscribers(subscribers)
                send_email(email, "Bienvenue à notre liste d'abonnement", "mail_bienvenue.html")
                flash("Merci pour votre abonnement. Vous recevrez des alertes par email.", "success")
        else:
            flash("Veuillez entrer une adresse email valide.", "danger")
        return redirect(url_for("home"))
    return render_template("index.html")

@app.route("/charts", methods=["GET"])
def charts():
    """Page pour afficher les graphiques générés."""
    charts = generate_charts()
    return render_template("charts.html", charts=charts)

if __name__ == "__main__":
    app.run(debug=True)
