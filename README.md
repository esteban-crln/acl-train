# ACL·train

Un simulateur pour s'entraîner aux ACL Cisco sur le réseau du TD « Architectures sécurisées »
(R5.Cyber.09, exercice 1) : un routeur Ro, un réseau serveurs, un réseau filaire, un réseau wifi,
une DMZ et Internet.

Le projet est écrit en HTML, CSS et JavaScript pur : pas de framework, rien à installer.

## Essayer en ligne

**https://esteban-crln.github.io/acl-train/**

Rien à télécharger : ouvrez le lien et tapez vos commandes dans la console. Tout se passe dans
votre navigateur, le simulateur ne touche à aucune vraie configuration.

## Lancer en local

Double-cliquez sur `index.html`. Les scripts sont des fichiers classiques (pas des modules), la page
fonctionne donc directement depuis le disque. Les polices viennent de Google Fonts ; hors ligne, la
page utilise les polices du système.

## Ce qu'on y trouve

- **Missions** : 13 exercices progressifs, de l'ACL standard au filtrage complet de la question 3 du
  TD. Chaque mission vérifie de vrais flux (« le wifi ne doit pas joindre l'intranet », « la réponse
  doit revenir »…). Indices progressifs, solution, étoiles.
- **Console Cisco simulée** : `access-list`, `ip access-list standard|extended`, `ip access-group`,
  `time-range` (`periodic`, `absolute`), `established`, `ip inspect`, NAT/PAT et redirection de ports,
  `show access-lists`, `show run`, `show ip interface`, abréviations (`conf t`, `int g0/1.1`), `?` et Tab.
  Les erreurs classiques sont expliquées : masque réseau à la place du masque générique,
  `access-list` au lieu de `access-group`, port sans `eq`, ligne jamais atteinte, `no access-list N …`
  qui efface toute l'ACL…
- **Testeur de paquets** : on choisit source, destination, service et moment ; le paquet est animé
  sur le schéma et la trace détaille chaque étape (ACL in, redirection, routage, NAT, ACL out,
  inspection, retour).
- **Bac à sable**, **quiz éclair** (masques génériques, « quelle ligne s'applique ? », cours, ports)
  et **mémo** du cours avec un calculateur de masque générique.

La progression et les configurations sont gardées dans le navigateur (localStorage).

## Arborescence

```
index.html        structure de la page, mémo
style.css         thèmes clair et sombre, mise en page
js/net.js         adresses IPv4, topologie du TD, services
js/router.js      configuration de Ro et interpréteur de commandes IOS
js/sim.js         trajet d'un paquet (ACL, NAT, redirection, inspection)
js/missions.js    missions, flux de test, contraintes
js/quiz.js        générateurs de questions
js/app.js         interface : console, schéma animé, testeur, progression
```

## Ordre de traitement simulé

Comme dans le cours : en entrée d'interface, l'ACL passe avant la redirection de ports ; en sortie,
la NAT passe avant l'ACL. L'inspection (`ip inspect`) autorise les réponses dans l'autre sens sur
l'interface où elle est appliquée.
