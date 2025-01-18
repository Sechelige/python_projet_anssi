from flask import Flask, render_template, request, redirect, url_for, flash

import re
import time
import threading
import os
import json

import feedparser
import requests
from email.mime.text import MIMEText
import smtplib
import pandas as pd

import plotly.express as px
import plotly.graph_objects as go
from plotly.utils import PlotlyJSONEncoder

"""
Cette classe permet de récupérer les nouvelles vulnérabilités publiées par l'ANSSI sur les flux RSS d'avis et d'alertes.
Les informations des vulnérabilités sont stockées dans un fichier CSV et les abonnés reçoivent des alertes par email lorsqu'une nouvelle vulnérabilité est détectée.
Le fichier csv est mis à jour à chaque nouvelle vulnérabilité détectée.

La classe est lancée en tant que thread pour surveiller en continu les flux RSS et détecter les nouvelles vulnérabilités et permet a l'application web de continuer à fonctionner normalement.
"""

"""
Extraction et enrichissement des données ANSSI via API
Enregistrement des données dans un fichier CSV - data_anssi.csv (Titre, Lien, Description, Type du bulletin, Date publication bulletin anssi, Editeur, Produits impactés, Versions concernés, CVE, CWE, CWE Description, CVSS Score, CVSS Severity, EPSS)
Type du fichier CSV : Dataframe Pandas 
"""	
class RSSMonitor:
    def __init__(self, app, csv_file):
        self.app = app
        self.csv_file = csv_file
        self.df = self._load_or_initialize_dataframe()
        self.stop_event = threading.Event()
        self.urls = [
            "https://www.cert.ssi.gouv.fr/avis/feed",
            "https://www.cert.ssi.gouv.fr/alerte/feed"
        ]
        self.thread = threading.Thread(target=self._monitor_rss, daemon=True)
        self.thread.start()
        print("Surveillance des flux RSS démarrée...")

    def _load_or_initialize_dataframe(self):

        return pd.read_csv(self.csv_file)
        

    def get_cve_info(self, cve_id):
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        uvl = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        try:
            response = requests.get(url, timeout=10, verify=True)
            response.raise_for_status()
            data = response.json()

            responsevl = requests.get(uvl, timeout=10, verify=True)
            responsevl.raise_for_status()
            datavl = responsevl.json()

            description = "Non disponible"
            if "containers" in data and "cna" in data["containers"]:
                cna = data["containers"]["cna"]
                if "descriptions" in cna and len(cna["descriptions"]) > 0:
                    description = cna["descriptions"][0].get("value", "Non disponible")

            cvss_score = "Non disponible"
            cvss_severity = "Non disponible"
            try:
                metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])
                if metrics:
                    if "cvssV3_1" in metrics[0]:
                        cvss_score = metrics[0]["cvssV3_1"]["baseScore"]
                    elif "cvssV3_0" in metrics[0]:
                        cvss_score = metrics[0]["cvssV3_0"]["baseScore"]

                    if cvss_score != "Non disponible":
                        cvss_score = float(cvss_score)
                        if cvss_score == 0:
                            cvss_severity = "None"
                        elif 0.01 <= cvss_score <= 3.99:
                            cvss_severity = "Low"
                        elif 4.0 <= cvss_score <= 6.99:
                            cvss_severity = "Medium"
                        elif 7.0 <= cvss_score <= 8.99:
                            cvss_severity = "High"
                        elif cvss_score >= 9.0:
                            cvss_severity = "Critical"
            except (IndexError, KeyError):
                pass

            cwe = "Non disponible"
            cwe_desc = "Non disponible"
            problemtype = data["containers"]["cna"].get("problemTypes", {})
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

            epss_score = "Non disponible"
            epss_data = datavl.get("data", [])
            if epss_data:
                epss_score = epss_data[0].get("epss", "Non disponible")

            return {
                "CVE": cve_id,
                "Description": description,
                "CVSS Score": cvss_score,
                "CVSS Severity": cvss_severity,
                "CWE": cwe,
                "CWE Description": cwe_desc,
                "EPSS": epss_score
            }

        except requests.exceptions.RequestException as e:
            print(f"Erreur lors de la récupération des informations pour le CVE {cve_id} : {e}")
            return None

    def _monitor_rss(self):
        while not self.stop_event.is_set():
            for feed_url in self.urls:
                rss_feed = feedparser.parse(feed_url)
                for entry in rss_feed.entries:
                    if entry.link not in self.df["Lien"].values:
                        print(f"Nouvelle entrée détectée : {entry.title}")

                        json_url = entry.link + "/json/"
                        try:
                            response = requests.get(json_url)
                            response.raise_for_status()
                            data = response.json()

                            editeur = "Non disponible"
                            if data.get("affected_systems"):
                                editeur = data["affected_systems"][0]["product"]["vendor"]["name"]

                            date_publication = "Non disponible"
                            if data.get("vendor_advisories"):
                                date_publication = data["vendor_advisories"][0]["published_at"]

                            produits = [sys["product"]["name"] for sys in data.get("affected_systems", [])]
                            versions = [sys.get("description", "") for sys in data.get("affected_systems", [])]

                            type_b = data["reference"].split("-")[2]
                            type_bulletin = "Avis" if type_b == "AVI" else "Alerte"

                            cve_list = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", str(data))))

                            for cve in cve_list:
                                cve_info = self.get_cve_info(cve)
                                if cve_info:
                                    row = {
                                        "Titre": entry.title,
                                        "Lien": entry.link,
                                        "Description": entry.description,
                                        "Type du bulletin": type_bulletin,
                                        "Date publication bulletin anssi": date_publication,
                                        "Editeur": editeur,
                                        "Produits impactés": ", ".join(produits),
                                        "Versions concernés": ", ".join(versions),
                                        "CVE": cve_info["CVE"],
                                        "CWE": cve_info["CWE"],
                                        "CWE Description": cve_info["CWE Description"],
                                        "CVSS Score": cve_info["CVSS Score"],
                                        "CVSS Severity": cve_info["CVSS Severity"],
                                        "EPSS": cve_info["EPSS"]
                                    }
                                    
                                    """ 
                                    Génération des alertes par email pour les abonnés
                                    """
                                    send_alert_email("Nouvelles vulnérabilités détectées", "mail_vulnerability.html")
                                    self.df = pd.concat([self.df, pd.DataFrame([row])], ignore_index=True)
                                    self.df.to_csv(self.csv_file, index=False)

                        except requests.exceptions.RequestException as e:
                            print(f"Erreur lors de la récupération des données pour le lien {entry.link} : {e}")
            time.sleep(60)

    def stop(self):
        self.stop_event.set()
        self.thread.join()
        print("Surveillance des flux RSS arrêtée.")

   
"""
Ici, nous initialisons une application web Flask et nous définissons les routes pour la gestion des abonnés et l'affichage des graphiques. 
cette application web permet aux utilisateurs de s'abonner à une liste de diffusion pour recevoir des alertes par email lorsqu'une nouvelle vulnérabilité est détectée.
Les graphiques interactifs sont générés à partir des données des vulnérabilités stockées dans le fichier CSV.
"""

# Chemin vers le fichier CSV 
CSV_FILE = "./database/data_anssi.csv"
# Chemin vers le fichier JSON pour stocker les abonnés
subscribers_file = os.path.join("./static/subscribers.json")
# Initialisation de l'application web Flask
app = Flask(__name__)
# Lancement du thread de surveillance des flux RSS
monitor = RSSMonitor(app, CSV_FILE)



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
    """
    from_email = "mailing.list.alert.anssi@gmail.com"
    # mot de d'application gnere par gmail (clé de sécurité)
    password = "joja qpfn chdg oiqr"

    with app.app_context():
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
    """Envoie un email d'alerte à toutes la mailing list.
    """

    subscribers = load_subscribers()
    for email in subscribers:
        send_email(email, subject, body)

def generate_charts(df):
    """Génère des graphiques interactifs à partir des données et les encode en JSON pour les afficher dans l'application web.
    """

    charts = {}

    try:
        # Histogramme des scores CVSS
        fig_cvss = px.histogram(df, x="CVSS Score", nbins=10, title="Distribution des scores CVSS",
                                labels={"CVSS Score": "Score CVSS"}, template="plotly_white")
        charts['cvss_histogram'] = json.dumps(fig_cvss, cls=PlotlyJSONEncoder)

        # Diagramme circulaire des types de vulnérabilités (CWE)
        fig_cwe = px.pie(df, names="CWE", title="Répartition des types de vulnérabilités (CWE)")
        charts['cwe_pie'] = json.dumps(fig_cwe, cls=PlotlyJSONEncoder)

        # Courbe des scores EPSS
        fig_epss = px.line(df, x=df.index, y="EPSS", title="Courbe des scores EPSS",
                           labels={"x": "Index", "EPSS": "Score EPSS"}, template="plotly_white")
        charts['epss_line'] = json.dumps(fig_epss, cls=PlotlyJSONEncoder)

        # Classement des Produits impactéss les plus affectés
        product_counts = df['Produits impactés'].value_counts().head(10)
        fig_products = px.bar(product_counts, orientation="h", title="Produits impactéss les plus affectés",
                              labels={"index": "Produits impactés", "value": "Nombre de vulnérabilités"},
                              template="plotly_white")
        charts['products_bar'] = json.dumps(fig_products, cls=PlotlyJSONEncoder)

        # Nuage de points entre CVSS et EPSS
        fig_scatter = px.scatter(df, x="CVSS Score", y="EPSS", color="CVSS Severity", size="EPSS",
                                 title="Relation entre CVSS et EPSS",
                                 labels={"CVSS Score": "Score CVSS", "EPSS": "Score EPSS"},
                                 template="plotly_white")
        charts['scatter_plot'] = json.dumps(fig_scatter, cls=PlotlyJSONEncoder)

        # Boxplot des scores CVSS par Editeur
        fig_boxplot = px.box(df, x="Editeur", y="CVSS Score", title="Distribution des scores CVSS par Editeur",
                             labels={"Editeur": "Editeur", "CVSS Score": "Score CVSS"},
                             template="plotly_white")
        charts['boxplot'] = json.dumps(fig_boxplot, cls=PlotlyJSONEncoder)

        # Évolution temporelle des vulnérabilités détectées
        df['Date publication bulletin anssi'] = pd.to_datetime(df['Date publication bulletin anssi'])
        vuln_per_date = df.groupby('Date publication bulletin anssi').size().reset_index(name='Nombre de vulnérabilités')
        fig_time = px.line(vuln_per_date, x="Date publication bulletin anssi", y="Nombre de vulnérabilités",
                           title="Évolution temporelle des vulnérabilités détectées",
                           labels={"Date publication bulletin anssi": "Date publication bulletin anssi", "Nombre de vulnérabilités": "Nombre"},
                           template="plotly_white")
        charts['time_series'] = json.dumps(fig_time, cls=PlotlyJSONEncoder)

    except Exception as e:
        print(f"Erreur lors de la génération des graphiques : {e}")

    return charts

@app.route("/", methods=["GET", "POST"])
def home():
    """Page d'accueil pour la gestion des abonnés a la mailing list.
    """
    
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
    """Page pour afficher les graphiques générés.
    """
    
    # Chargement des données des vulnérabilités depuis le fichier CSV (charger a chaque fois pour avoir les données les plus récentes)
    CSV_FILE = "./database/data_anssi.csv"
    df = pd.read_csv(CSV_FILE)

    # Nettoyage des données avant de les afficher dans les graphiques
    df.drop_duplicates(inplace=True)
    df.replace("Non disponible", pd.NA, inplace=True)
    df.dropna(inplace=True)
    df['CVSS Score'] = pd.to_numeric(df['CVSS Score'], errors='coerce')
    df['EPSS'] = pd.to_numeric(df['EPSS'], errors='coerce')
    ##############################################################

    # Génération des graphiques
    charts = generate_charts(df)

    return render_template("charts.html", charts=charts)

# Lancement de l'application web Flask
if __name__ == "__main__":

    app.run(debug=True, port=5002)
    # Arrêt du thread de surveillance des flux RSS lors de l'arrêt de l'application web
    monitor.stop()
