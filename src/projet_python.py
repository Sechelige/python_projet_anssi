import feedparser
import requests
import re
import time


# URL du flux RSS
url = "https://www.cert.ssi.gouv.fr/avis/feed"
rss_feed = feedparser.parse(url)

# Initialisation d'une liste pour stocker les liens utiles
rss_links = []

# Parcours des entrées du flux RSS
for entry in rss_feed.entries:
    rss_links.append(entry.link)  # On ne récupère que le lien ANSSI

# Liste pour stocker tous les CVE trouvés
all_cve_list = []

# Fonction pour extraire les CVE d'un lien JSON
def extract_cves_from_json(link):
    json_url = link + "/json/"
    try:
        response = requests.get(json_url, timeout=10)
        response.raise_for_status()  # Vérifie si la requête a réussi
        data = response.json()
        
        # Extraction des CVE via une regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list = list(set(re.findall(cve_pattern, str(data))))  # Extraction unique des CVE
        return cve_list
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des données JSON pour {link}: {e}")
        return []

# Extraction des CVE pour chaque lien
for link in rss_links:
    cve_list = extract_cves_from_json(link)
    all_cve_list.extend(cve_list)

# print propre des CVE
print("\nListe des CVE trouvés :")
print (all_cve_list)

# Récupération des informations sur les CVE
cve_data = []

def get_cve_info(cve_id):
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    epss_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"

    try:
        # Récupération des données CVE
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        cve_info = response.json()

        # Description
        description = "Non disponible"
        if "containers" in cve_info and "cna" in cve_info["containers"]:
            descriptions = cve_info["containers"]["cna"].get("descriptions", [])
            if descriptions:
                description = descriptions[0].get("value", "Non disponible")

        # CVSS
        cvss_score = "Non disponible"
        metrics = cve_info["containers"]["cna"].get("metrics", [])
        if metrics:
            if "cvssV3_1" in metrics[0]:
                cvss_score = metrics[0]["cvssV3_1"]["baseScore"]
            elif "cvssV3_0" in metrics[0]:
                cvss_score = metrics[0]["cvssV3_0"]["baseScore"]

        # CWE
        cwe = "Non disponible"
        cwe_desc = "Non disponible"
        problem_types = cve_info["containers"]["cna"].get("problemTypes", [])
        if problem_types:
            cwe = problem_types[0]["descriptions"][0].get("cweId", "Non disponible")
            cwe_desc = problem_types[0]["descriptions"][0].get("description", "Non disponible")

        # EPSS
        response_epss = requests.get(epss_url, timeout=10)
        response_epss.raise_for_status()
        epss_data = response_epss.json().get("data", [])
        epss_score = epss_data[0]["epss"] if epss_data else "Non disponible"

        return {
            "CVE": cve_id,
            "Description": description,
            "CVSS Score": cvss_score,
            "CWE": cwe,
            "CWE Description": cwe_desc,
            "EPSS": epss_score
        }

    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des informations pour {cve_id}: {e}")
        return None

# Récupération des données pour chaque CVE
for cve in set(all_cve_list):  # Utilisation de set pour éviter les doublons
    info = get_cve_info(cve)
    if info:
        cve_data.append(info)
print (cve_data)
# Affichage final
print("\nDonnées des CVE extraites :")
for cve_info in cve_data:
    print(cve_info)
