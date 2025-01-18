# Surveillance et Enrichissement des Vulnérabilités ANSSI

## Description du projet

Ce projet Python vise à surveiller en continu les flux RSS d'avis et d'alertes publiés par l'Agence Nationale de la Sécurité des Systèmes d'Information (ANSSI). Les vulnérabilités détectées sont enrichies à l'aide d'API externes, consolidées dans un fichier CSV, et analysées pour produire des graphiques interactifs. Les utilisateurs peuvent également s'abonner pour recevoir des alertes personnalisées par e-mail lorsque de nouvelles vulnérabilités sont détectées.

## Fonctionnalités principales

1. **Extraction des données ANSSI** : Surveillance des flux RSS pour détecter les nouvelles vulnérabilités.
2. **Enrichissement des vulnérabilités (CVE)** :
   - Utilisation de l'API CVE de MITRE pour les descriptions, scores CVSS et types CWE.
   - Utilisation de l'API EPSS pour évaluer la probabilité d'exploitation.
3. **Consolidation des données** : Stockage des informations dans un fichier CSV structuré avec Pandas.
4. **Visualisation interactive** : Génération de graphiques avec Plotly pour analyser les vulnérabilités.
5. **Alerte et notification par e-mail** : Envoi automatique d'e-mails d'alerte aux abonnés pour les vulnérabilités critiques.

## Installation

1. **Prérequis** :
   - Python 3.8 ou supérieur.
   - Bibliothèques Python nécessaires :
     ```bash
     pip install flask pandas feedparser requests plotly smtplib
     ```
   - Configurer un compte Gmail pour l'envoi d'e-mails (un compte specifique a deja ete creer.) :
     - Activer l'accès à l'application pour générer un mot de passe d'application.


2. **Cloner le dépôt** :
   ```bash
   git clone [https://github.com/Sechelige/python_projet_anssi]
   cd [src/webb_app]
   ```

3. **Structure du projet** :
   ```
   ├── app.py                   # Code principal de l'application Flask
   ├── static/
   │   └── subscribers.json     # Fichier JSON pour les abonnés (mailing list)
   ├── database/
   │   └── data_anssi.csv       # Fichier CSV pour les vulnérabilités consolidées
   ├── templates/
   │   ├── index.html           # Page d'accueil
   │   ├── charts.html          # Page pour les graphiques
   │   └── mail_vulnerability.html  # Modèle pour les alertes par e-mail
   ├── README.md                # Fichier explicatif du projet
   ```

## Utilisation

1. **Lancer l'application** :
   ```bash
   python3 app.py
   ```
   L'application sera disponible sur `http://127.0.0.1:5002`.

2. **Fonctionnalités web** :
   - Page d'accueil : S'abonner à la liste de diffusion pour recevoir des alertes.
   - Page des graphiques : Visualiser les vulnérabilités et leurs analyses.

3. **Gestion des flux RSS et des abonnés** :
   - L'application surveille les flux RSS toutes les 60 secondes.
   - Les nouvelles vulnérabilités sont automatiquement ajoutées au fichier CSV et enrichies.

## Points importants

- **Gestion des ressources externes** :
  - Des délais entre les requêtes aux API (Rate Limiting) sont implémentés pour éviter la surcharge des serveurs.
  - Les flux RSS et réponses JSON peuvent être pré-téléchargés pour limiter les interactions avec les sites externes.
- **Sécurité** :
  - Veillez à ne pas partager vos identifiants Gmail et mot de passe d'application.

## Visualisations générées

Les graphiques incluent :
- Histogrammes des scores CVSS.
- Diagrammes circulaires pour les types CWE.
- Nuages de points entre CVSS et EPSS.
- Classements des produits et éditeurs les plus affectés.

## Auteurs

- Projet réalisé par Maryam B., Louis E. et moi meme Antoine D., dans le cadre du cours de programmation Python à l'ESILV (2024).