# Clients

GWyl Mail n'est pas un client mail. Il ne se connecte pas à une boîte et il ne remplace pas l'éditeur.

Thunderbird peut s'en servir. À l'envoi, le greffon joint la preuve au message déjà écrit et laisse Thunderbird l'envoyer. Si la preuve ne peut pas être signée, l'envoi est annulé.

L'heure, quand elle est là, vient d'un jeton RFC 3161. Sans adresse de serveur d'horodatage dans `GWYL_TSA_URL` ou `.gwyl_mail/tsa.url`, la preuve n'en a pas. Le certificat de ce serveur se place dans `.gwyl_mail/tsa-ca.pem`.


Gmail ne le peut pas aujourd'hui. Outlook peut, par un greffon, mais ce n'est pas mesuré.

La preuve emporte le texte signé, avec sa mise en forme, et les pièces jointes. Une mention ou un bandeau ajouté avant ou après ce texte est signalé et ne le rend pas faux. Du texte au milieu, ou à la place, est un refus. Cet écart n'est accepté que si la preuve est signée : une preuve non signée peut être réécrite en même temps que le message.
