"""
Script de reconnaissance passive - Phase 1 PyAudit
Interroge des bases de données publiques SANS envoyer de trafic vers la cible.
"""

import socket       # Pour les résolutions DNS
import json         # Pour lire les réponses JSON de crt.sh
import urllib.request  # Pour faire des requêtes HTTP (inclus dans Python, pas besoin d'installer)
import urllib.error
from datetime import datetime


# ─────────────────────────────────────────────
# 1. RÉSOLUTION DNS
# Pose la question : "quelle(s) adresse(s) IP correspond à ce domaine ?"
# On interroge le serveur DNS configuré sur notre machine, pas la cible.
# ─────────────────────────────────────────────
def lookup_dns(domaine: str) -> list[str]:
    """Retourne la liste des adresses IP associées au domaine."""
    try:
        # getaddrinfo retourne une liste de tuples, on extrait juste les IPs
        resultats = socket.getaddrinfo(domaine, None)
        # On déduplique avec un set, puis on retrie
        ips = sorted(set(r[4][0] for r in resultats))
        return ips
    except socket.gaierror as e:
        # gaierror = "getaddrinfo error", domaine introuvable ou réseau coupé
        return [f"Erreur DNS : {e}"]


# ─────────────────────────────────────────────
# 2. CERTIFICATS TLS via crt.sh
# crt.sh est une base publique qui enregistre TOUS les certificats TLS émis.
# Chaque sous-domaine qui a eu un certificat HTTPS y apparaît.
# On interroge leur API JSON — on ne touche pas la cible.
# ─────────────────────────────────────────────
def lookup_crtsh(domaine: str) -> list[str]:
    """Retourne les sous-domaines trouvés dans les certificats TLS publics."""
    url = f"https://crt.sh/?q=%.{domaine}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PyAudit-Recon/1.0"})
        with urllib.request.urlopen(req, timeout=10) as reponse:
            donnees = json.loads(reponse.read().decode())

        # Chaque entrée a un champ "name_value" qui peut contenir plusieurs lignes
        sous_domaines = set()
        for entree in donnees:
            for nom in entree.get("name_value", "").split("\n"):
                nom = nom.strip().lstrip("*.")  # Supprime les wildcards *.
                if nom and domaine in nom:
                    sous_domaines.add(nom)

        return sorted(sous_domaines)

    except urllib.error.URLError as e:
        return [f"Erreur réseau : {e}"]
    except json.JSONDecodeError:
        return ["Erreur : réponse non JSON (crt.sh peut être surchargé)"]


# ─────────────────────────────────────────────
# 3. AFFICHAGE DU RAPPORT
# ─────────────────────────────────────────────
def afficher_rapport(domaine: str):
    separateur = "─" * 50

    print(f"\n{'═' * 50}")
    print(f"  RAPPORT DE RECONNAISSANCE PASSIVE")
    print(f"  Cible   : {domaine}")
    print(f"  Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═' * 50}")

    # --- DNS ---
    print(f"\n[DNS] Résolution d'adresses IP")
    print(separateur)
    ips = lookup_dns(domaine)
    for ip in ips:
        print(f"  → {ip}")

    # --- crt.sh ---
    print(f"\n[CRT.SH] Sous-domaines dans les certificats TLS")
    print(separateur)
    print("  (interrogation de crt.sh en cours...)")
    sous_domaines = lookup_crtsh(domaine)
    if sous_domaines:
        for sd in sous_domaines[:20]:  # On limite à 20 pour ne pas noyer l'affichage
            print(f"  → {sd}")
        if len(sous_domaines) > 20:
            print(f"  ... et {len(sous_domaines) - 20} autres")
    else:
        print("  Aucun sous-domaine trouvé.")

    print(f"\n{'═' * 50}\n")


# ─────────────────────────────────────────────
# POINT D'ENTRÉE DU SCRIPT
# Ce bloc ne s'exécute que si on lance directement ce fichier
# (pas si on l'importe depuis un autre script)
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    # Si on passe un domaine en argument : python recon_passive.py google.com
    # Sinon on utilise example.com par défaut
    domaine = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    afficher_rapport(domaine)
