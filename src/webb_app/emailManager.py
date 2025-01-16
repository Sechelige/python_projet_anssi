from flask import Flask, render_template, request, redirect, url_for, flash
import smtplib
from email.mime.text import MIMEText
import json
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.utils import PlotlyJSONEncoder
from RSSMonitor import RSSMonitor 
import time

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