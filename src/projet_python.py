import feedparser
import requests
import re
import time

#URL du flux RSS
url = "https://www.cert.ssi.gouv.fr/avis/feed"
rss_feed = feedparser.parse(url)

#Initialisation d'une liste pour stocker les informations
rss_data = []

#Parcours des entrées du flux RSS
for entry in rss_feed.entries:
    # Création d'un dictionnaire pour chaque entrée
    rss_entry = {
        "Titre": entry.title,
        "Description": entry.description,
        "Lien": entry.link,
        "Date": entry.published
    }

    # Ajout du dictionnaire à la liste
    rss_data.append(rss_entry)

#Affichage du tableau (liste de dictionnaires)
print(rss_data)

#Liste pour stocker tous les CVE trouvés dans chaque lien RSS
all_cve_list = []

#Parcours des éléments dans rss_data
for entry in rss_data:
    # Construction de l'URL JSON en ajoutant '/json/' à l'URL de base
    json_url = entry["Lien"] + "/json/"

    try:
        # Requête HTTP pour récupérer les données JSON
        response = requests.get(json_url)
        response.raise_for_status()  # Vérifie si la requête a réussi

        # Chargement du contenu JSON
        data = response.json()

        # Extraction des références CVE à partir de la clé "cves"
        ref_cves = list(data.get("cves", []))  # Assure-toi que "cves" existe dans la réponse

        # Extraction des CVE via une regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list = list(set(re.findall(cve_pattern, str(data))))  # Extraction des CVE

        # Ajout des CVE extraits à la liste globale
        all_cve_list.extend(cve_list)

        # Affichage des informations de l'alerte et des CVE
        #print(f"Alerte: {entry['Titre']}")
        #print("CVE trouvés :", cve_list)

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des données pour l'alerte {entry['Titre']} : {e}")

#Affichage de tous les CVE extraits
print("\nTous les CVE extraits depuis les flux RSS:")
print(all_cve_list)

cve_data = [] # créer une liste pour stocker les inofs des cve

# Fonction pour récupérer les informations d'un CVE via l'API
def get_cve_info(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        response = requests.get(url, timeout=10, verify=False)
        response.raise_for_status()  # Vérifie si la requête a réussi
        data = response.json()

        # Extraire la description
        description = data["containers"]["cna"]["descriptions"][0]["value"]

        # Extraire le score CVSS
        cvss_score = "Non disponible"
        try:
            containers = data.get("containers", {})
            if containers:
                cna = containers.get("cna", {})
                if cna and "metrics" in cna:
                    metrics = cna["metrics"]
                    if metrics:
                        # Vérification de la présence de cvssV3_1 ou cvssV3_0
                        if "cvssV3_1" in metrics[0]:
                            cvss_score = cna["metrics"][0]["cvssV3_1"]["baseScore"]
                        elif "cvssV3_0" in metrics[0]:
                            cvss_score = cna["metrics"][0]["cvssV3_0"]["baseScore"]
        except (IndexError, KeyError):
            cvss_score = "Non disponible"

        # Extraire le CWE et sa description
        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        problemtype = data["containers"]["cna"].get("problemTypes", {})
        if problemtype and "descriptions" in problemtype[0]:
            cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

        # Ajouter les données du CVE à la liste
        cve_info = {
            "CVE": cve_id,
            "Description": description,
            "CVSS Score": cvss_score,
            "CWE": cwe,
            "CWE Description": cwe_desc
        }

        return cve_info
    
    except requests.exceptions.Timeout:
        print(f"Erreur de délai d'attente pour le CVE {cve_id}. La requête a été annulée après 10 secondes.")
        return None
    
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des informations pour le CVE {cve_id} : {e}")
        return None


# Récupérer les informations pour chaque CVE dans la liste
for cve in all_cve_list:
    cve_info = get_cve_info(cve)
    if cve_info:
        cve_data.append(cve_info)
    time.sleep(1)  # Attendre 1 seconde entre chaque requête

# Affichage des données des CVE
print("\nDonnées des CVE extraites :")
for data in cve_data:
    print(data)
