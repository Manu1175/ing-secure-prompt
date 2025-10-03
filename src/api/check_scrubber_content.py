# src/api/check_scrubber_content.py
import os

scrubber_path = r"src\api\scrubber.py"
abs_path = os.path.abspath(scrubber_path)

print("="*60)
print("DIAGNOSTIC DU FICHIER SCRUBBER.PY")
print("="*60)
print(f"Chemin: {abs_path}")

if not os.path.exists(scrubber_path):
    print(f"\n❌ Fichier introuvable: {scrubber_path}")
    raise SystemExit(1)

size = os.path.getsize(scrubber_path)
with open(scrubber_path, 'r', encoding='utf-8') as f:
    content = f.read()

print(f"\n📊 Taille du fichier: {size} octets")
print(f"📊 Nombre de lignes: {len(content.splitlines())}")

if size == 0:
    print("\n❌ Le fichier existe mais est VIDE (0 octet). Remplace le contenu par la version fournie.")
else:
    if "class Scrubber" in content:
        print("\n✅ Classe 'Scrubber' trouvée")
    else:
        print("\n❌ Classe 'Scrubber' ABSENTE")

    if "from audit import" in content or "from src.api.audit import" in content:
        print("✅ Import audit présent (ou fallback)")
    else:
        print("⚠️  Import audit manquant ou incorrect")

    if "import spacy" in content:
        print("✅ Import spacy présent (optionnel)")
    else:
        print("ℹ️  spaCy non importé (NER sera désactivé si absent)")
print("\n" + "="*60)
