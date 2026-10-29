# Deux portes, un seul envoi

Thunderbird laisse un greffon voir le message avant l'envoi. Gmail et Outlook non : ils fabriquent le message après le clic.

| Où la personne écrit | Ce qui part |
|---|---|
| Thunderbird, greffon activé | Le greffon donne le texte à l'application locale. C'est elle qui fige le message, joint la preuve et l'envoie. Thunderbird n'envoie pas une deuxième copie. |
| Gmail ou Outlook | Pas de greffon. La personne écrit dans l'application locale. Le serveur de sa boîte ne fait que transporter le message déjà terminé. |

Le mot de passe du compte reste dans `.gwyl_mail/account.json` sur cette machine. Il n'entre pas dans le message. itsme reste une option, désactivée par défaut.
