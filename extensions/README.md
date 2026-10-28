# Extensions

Les deux extensions ne vérifient rien elles-mêmes. Elles envoient le message brut à l'interface locale, qui refuse de s'ouvrir ailleurs que sur `127.0.0.1`.

```bash
gwyl-mail ui
```

Puis ouvrir http://127.0.0.1:8765/

| Dossier | Où l'installer |
|---|---|
| `extensions/browser` | Chrome ou Firefox, « Charger l'extension non empaquetée » |
| `extensions/thunderbird` | Thunderbird 115+, « Installer un module depuis un fichier » après avoir zipé ce dossier, ou chargement temporaire |

Une preuve non signée est refusée, sauf si la case « preuve dégradée » est cochée. Deux pièces jointes `gwylproof.json` dans le même message sont refusées.
