# fobots

*[English version](README.md)*

> *« fo » signifie « filter out » ! À quoi pensiez-vous ?* (« *'fo' stands for filter out! What were you thinking?* »)

Les messages, le journal et l'aide en ligne du programme sont en anglais.

Démon qui protège un serveur web (nginx ou Apache) des
scrapers trop agressifs. Il suit l'access log, repère les **plages d'IP** dont le
débit dépasse un seuil, et les ajoute à un set **nftables** avec expiration : le
trafic est rejeté par le pare-feu avant d'atteindre le serveur web.

> **Statut : preuve de concept (POC).** Ce logiciel a été *vibe codé* (écrit avec un assistant
> d'IA) et est encore en phase de test. Il a des tests unitaires et d'intégration, et il a déjà
> permis de ressusciter un serveur qui ne pouvait plus répondre aux sollicitations à cause de
> scrapers (charge de plus de 35 ramenée à 0,2). Les autres fonctions (unité systemd
> d'exemple, durcissement selon la charge, IPv6, surveillance `watch_*`) n'ont été testées
> qu'avec un faux `nft`. Il n'a **pas été relu par d'autres humains que son auteur** : toutes
> les contributions sont les bienvenues. Il modifie le pare-feu : un bogue ou un mauvais
> réglage peut couper des visiteurs légitimes, ou vous-même. Relisez le code avant de vous y
> fier, essayez-le d'abord avec `--dry-run` (et `trap_ban = no`), et gardez un accès à la
> machine hors de ce chemin réseau.

Python 3.7+ standard (aucune dépendance), nftables, Linux.

## Fonctionnement

1. Chaque ligne du log (format *combined* nginx/Apache) est rattachée à
   une plage d'IP : celle de l'allocation RIR qui la contient (obtenue par RDAP,
   le successeur de whois). Le détail du propriétaire n'est pas conservé : seule
   la plage compte.
2. Les requêtes sont comptées par plage et par seconde. Quand une plage dépasse
   `threshold` req/s (pendant `sustain` secondes consécutives, 5 par défaut : le chargement d'une page est une courte salve), elle est bannie pour
   `ban_time`.
3. Les plages inconnues ne sont pas interrogées au hasard : RDAP n'est appelé
   (en tâche de fond) que pour un préfixe `/16` (`/32` en IPv6) qui dépasse déjà
   `prefix_threshold` req/s, avec un budget horaire, un délai entre requêtes et
   une pause sur HTTP 429. Les plages trouvées sont enregistrées sur disque
   (`ip_ranges.json`) et réutilisées.
4. Par défaut (`ban_scope = observed`), le ban se resserre sur les IP réellement vues dans
   l'allocation : voir « Ban resserré » plus bas. Avec `ban_scope = allocation`, il couvre
   **toute l'allocation**.
5. Le ban est une transaction nft unique. Une plage déjà couverte par un ban plus
   large est ignorée ; une plage qui en englobe d'autres les remplace.
6. L'état des bans est **dans nft** (lu au démarrage) : le démon peut être
   relancé sans perte, et chaque ban expire seul.

## Installation

Sur Debian/Ubuntu, depuis un clone du dépôt :

```
sudo ./fobots.py install --dry-run            # le plan, sans rien modifier
sudo ./fobots.py install --log /var/log/nginx/access.log
```
La commande est **idempotente** (on peut la relancer pour mettre à jour le programme et
l'unité) et ne touche jamais une conf ou une liste welcome existantes. Elle :

1. vérifie Python (3.7+) et installe `nftables` avec apt-get si `nft` manque (demande
   confirmation, ou `--yes`) ;
2. **teste nft** sur une table jetable : sets d'intervalles avec expiration, sortie JSON
   lisible (s'arrête avec un message sinon) ; signale si cette version n'indique pas le
   temps restant des bans ;
3. crée l'utilisateur système `fobots` s'il manque ;
4. installe la commande `/usr/local/sbin/fobots` (le lanceur, sans `.py`) et ses modules dans
   `/opt/fobots/fobots/`, la conf dans `/etc/fobots/fobots.conf` (avec
   `--log` s'il est donné), une liste welcome vide `/etc/fobots/welcome.txt`, le dossier
   d'état `/var/lib/fobots` (0750, propriété de `fobots`) ;
5. installe l'unité systemd, avec le groupe qui donne accès au log (détecté, sinon `adm` ;
   `--log-group` pour l'imposer), puis `systemctl daemon-reload` ;
6. vérifie que l'utilisateur `fobots` peut lire le log, et dit quoi faire sinon.

Le service n'est **ni activé ni démarré** par défaut : adapter la conf, remplir la liste
welcome, essayer `fobots run --dry-run`, puis `systemctl enable --now fobots`
(ou relancer `install` avec `--enable` / `--start`). `--destdir DIR` écrit les fichiers sous
un préfixe sans toucher au système (tests, empaquetage).

À la main, sans `install` :

```
./fobots.py setup                          # crée la table nft (idempotent)
cp fobots.conf.example fobots.conf         # puis adapter log, seuils
./fobots.py run --dry-run -v               # affiche les bans sans toucher à nft
sudo ./fobots.py run -f fobots.conf        # le vrai démon (en root : -f, voir Configuration)
```

Pour un service permanent, voir `fobots.service.example` (utilisateur dédié,
`CAP_NET_ADMIN` seulement, durcissement systemd).

Commencer prudemment : `ban_time = 10m`, un seuil qui ne vise que les cas
évidents, et garder une session ouverte (voir « Remise à zéro »).

### Paquet Debian

```
make                 # construit dist/fobots_0.N_all.deb  (N = nombre de commits)
make VERSION=1.0.0   # impose la version
make check           # vérification de syntaxe
make upgrade         # tests, construction, puis sudo dpkg -i (redémarre un service actif)
make lint            # lintian
sudo apt install ./dist/fobots_*_all.deb
```
Le paquet installe les mêmes fichiers que `install` (commande `/usr/sbin/fobots`, modules dans `/opt/fobots/fobots/`, conf et
`welcome.txt` dans `/etc/fobots` en conffiles, unité systemd) et ne démarre pas le service.
Une mise à jour relance seulement un service déjà démarré ; `purge` supprime
`/var/lib/fobots` et l'utilisateur `fobots`.

### Tests

```
make test            # python3 -m unittest discover -s tests  (bibliothèque standard, environ 1 s)
```
La suite couvre le regroupement des plages, les bans (dont le contournement du chevauchement
nft), la détection avec et sans `ban_scope = observed`, les niveaux de charge, les erreurs de
configuration, la rotation des logs et les commandes (`run --dry-run`, `welcome`, `watched`,
`install --destdir`). Aucun test n'exige root ni un vrai `nft`.

```
make integration     # tests/integration.sh : le vrai nft et le vrai noyau, avec des logs fictifs
```
Le test d'intégration rejoue des logs générés dans le vrai démon et vérifie le vrai set nft :
bans d'allocation entière et resserrés, un ban plus large qui en remplace de plus petits (le cas
que nft 0.9.x refuse en une seule transaction), `welcome add`, IPv6 et l'expiration par le noyau.
Il s'exécute dans un espace de noms utilisateur+réseau jetable (`unshare -Urn`) : sans root, et
les règles nft de la machine ne sont jamais touchées. À lancer avec la plus ancienne version de
nft prise en charge (0.9.3).

## Durcissement selon la charge

Désactivé par défaut (`load_signal = none`). Quand il est actif, un thread mesure
la charge toutes les 5 s :

- `psi` : pression `/proc/pressure` (max de cpu et io, `some avg10`, en %), très
  réactive ; repli automatique sur `loadavg` si le noyau ne l'offre pas ;
- `loadavg` : charge sur 1 minute divisée par le nombre de cœurs (plus lente) ;
- `probe` : **le temps de réponse du service lui-même**, l'indicateur le plus fidèle quand
  ce qu'on protège est un site qui se dégrade (un serveur peut être saturé en processus
  Apache ou en connexions à la base avec un CPU au repos). Un `GET` par URL toutes les 5 s,
  depuis la machine :

  ```ini
  load_signal = probe
  load_probe_url = www.example.org@http://127.0.0.1/app/une-page-dynamique
  # load_tense = 1       # secondes (défaut)
  # load_critical = 3
  # load_probe_timeout = 10s   # une réponse plus lente compte pour 10 s
  ```
  `HOTE@` fixe l'en-tête `Host` (vhost) ; plusieurs URL se séparent par des virgules, le
  niveau suit la plus lente. Choisis une **page dynamique typique de ton service**, qui
  répond en 2xx : le démon refuse de démarrer sinon (une redirection ou un 404 ne
  mesureraient rien). Une erreur de connexion ou un HTTP 5xx ne compte comme critique qu'après
  3 échecs consécutifs. La sonde vient de `127.0.0.1` : adresse privée, donc jamais comptée ni
  bannie. Elle est choisie par toi, jamais tirée du log. `fobots probe` mesure l'URL pendant
  une minute (médiane, p95, max) pour t'aider à choisir les niveaux ; relance-la pendant un
  ralentissement pour voir à quoi ressemble « dégradé ».

### Enregistrer à quoi ressemble un ralentissement (avant de configurer quoi que ce soit)

`fobots probe` fonctionne sans configuration et sans installation (`./fobots.py probe …`).
Laissé en route sur une machine, il enregistre l'état du serveur quand la page ralentit :

```
./fobots.py probe --url HOTE@http://127.0.0.1/app/page --record probe.jsonl      # lancé à la main (nohup, tmux…)
./fobots.py probe --report probe.jsonl
```

Il mesure la page toutes les 5 s et garde en mémoire les deux dernières minutes de relevés
(seul `/proc` est lu : charge, mémoire disponible, activité de swap, pression, file d'accept des
ports 80/443, ListenOverflows). Quand le temps de réponse atteint `--load-tense` (1 s par
défaut), il écrit ces deux minutes, puis un instantané complet (avec les processus qui
consomment le plus de mémoire, regroupés par nom : les workers du backend, pas seulement le
serveur web) toutes les 10 s tant que le ralentissement dure, et aussitôt qu'il devient
critique (3 s). Un relevé des périodes normales est ajouté toutes les 5 minutes pour comparer.
Le fichier est renommé `FILE.1` au-delà de 20 Mo.

`--report` liste les ralentissements et indique **quel relevé a bougé le premier, et de
combien de temps** (colonnes *before / same / late / never*, avance médiane, et part des
relevés normaux déjà au-delà de la valeur : une fausse alerte). Les valeurs utilisées (charge
≥ 1 par cœur, pression ≥ 20 % (5 % pour la mémoire), mémoire disponible ≤ 15 %, swap ≥ 100
pages/s, file d'accept ≥ 1) sont des repères, pas des recommandations : il s'agit de voir,
sur **ta** machine, quel signal mérite d'être utilisé. Laisse-le tourner jusqu'à quelques
ralentissements.

Le rapport sépare les **incidents** (plus de 20 s, ou atteignant le niveau critique) des **excursions
courtes** (gigue du service : comptées et résumées, pas listées). Seuls les incidents servent à comparer les
relevés et à dimensionner les paliers. Une connexion qui échoue n'a pas de temps de réponse : elle compte comme
le timeout de la sonde, et `load_critical` n'est jamais suggéré au-delà de sa moitié, car au-delà du timeout
le démon ne distingue plus les réponses (un effondrement à 40 s et un à 10 s se ressemblent).

À la fin, `--report` écrit une **configuration suggérée** d'après ce qui a été enregistré :
`load_probe_url` (conservée dans une ligne d'en-tête du fichier), `load_tense` (au-dessus de la gigue
normale et des excursions de 20 s ou moins qui ne sont pas des ralentissements) et `load_critical` (sous
le pic médian des vrais ralentissements), chaque ligne avec sa justification, et un **rejeu** des règles
du démon sur l'enregistrement (« avec 1 s / 3 s tu aurais été tendu 38 % du temps ; avec 1,5 s / 4 s,
12 % »). Si un relevé que le démon sait lire (`psi`, `loadavg`) a bougé avant la page dans au moins deux
tiers des ralentissements, avec au moins 20 s d'avance et moins de 5 % de fausses alertes, il est proposé
en alternative (le démon prend un seul signal) ; les autres relevés sont seulement signalés. Un arrêt propre (Ctrl-C, SIGTERM) est écrit dans le fichier et compte comme une pause, hors de la
durée. Un silence qui n'a pas été demandé est la machine en difficulté : l'enregistreur qui cale
lui-même (il revient seul) ou une exécution coupée sans arrêt (tuée, machine redémarrée) sont listés
comme *interruptions inattendues*, restent dans la durée, et comptent comme ralentissements sévères
quand elles durent 5 s ou plus.

Rien n'est
suggéré sans assez de données : 500 mesures normales sur 2 heures pour les paliers, ou 3 ralentissements
de 5 s ou plus (une machine attaquée ne donnera pas des heures de temps normal), et 3 ralentissements
pour comparer les signaux. Les valeurs sont un point de départ : à revoir après le premier vrai incident.

Ajoute `--log /var/log/nginx/access.log` (répétable) pour coupler l'enregistrement aux logs d'accès :
chaque mesure stocke alors aussi les requêtes/s, la part de réponses 5xx (un backend saturé) et le
nombre d'IP distinctes arrivées depuis la précédente, et le rapport ajoute deux lignes : *requêtes/s ≥
2× la médiane normale* distingue un pic de trafic d'une cause interne (sauvegarde, cron, base lente),
et la part de 5xx montre quand le backend a commencé à défaillir. Le log est seulement lu (depuis sa
fin), jamais pris dans la configuration, et une rotation est suivie.

Trois niveaux : *normal*, *tendu*, *critique*. On y monte immédiatement ; on
redescend d'un niveau seulement après `load_recover` continu sous le palier. À
chaque niveau, **le seuil et la durée de ban sont multipliés** par le facteur
(0.5 puis 0.25 par défaut), sans descendre sous `min_threshold` / `min_ban_time` :
des règles plus sévères mais des bans plus courts, donc des plages rejugées plus
vite. `prefix_threshold` suit le même facteur. Exemple (base 10 req/s, 1 h) :
tendu = 5 req/s pendant 30 min, critique = 2,5 req/s pendant 15 min.

Les paliers par défaut ne sont **pas calibrés** sur ton serveur : lance d'abord
avec `--dry-run -v` et regarde les lignes `load: psi=…` (toutes les 5 minutes et
à chaque changement de niveau) pour choisir `load_tense` / `load_critical`.
Les faux positifs se corrigent avec `welcome add`.

## Tester la tenue en charge en rejouant un log

`fobots stress` rejoue les requêtes `GET` d'un log d'accès contre un serveur, à un débit que tu choisis, par
paliers croissants, et mesure. Il répond à *quelles requêtes sont coûteuses, et à quelle charge le service cède*, sans
attendre le prochain incident et sans toucher au format du log.

```
./fobots.py stress /var/log/nginx/access.log --base https://www.example.org --agent 'bot|crawl|spider' \
        --rate 2,5,10,15 --step 3m --probe-url HOTE@http://127.0.0.1/app/page
./fobots.py stress --report stress.jsonl        # relit les résultats
```

- **La charge.** `--rate` est le nombre de requêtes par seconde infligées au serveur, palier par palier (2,5,10,15
  par défaut), régulièrement espacées ; `--step` est la durée d'un palier (3m). Les requêtes sont prises dans
  l'ordre du log à partir d'une **position aléatoire** (affichée avec sa `--seed`, pour refaire un essai ;
  `--from/--until` bornent la partie du log où elle est tirée), et reprennent au début à la fin du log : chaque
  palier envoie les mêmes requêtes, plus vite. Si un palier demande plus de requêtes que le log n'en a, le plan le
  dit (les caches se réchauffent). `--agent` et `--ignore-path` (expressions régulières) choisissent ce qui est
  rejoué : par exemple seulement les robots, et pas les pages bon marché qui ne disent rien de la charge.
  `--ignore-path` est par défaut le `ignore_path` de la configuration, avec les règles de chaque
  `[site:NOM]`, comme pour `run` et `analyse` ; le plan indique combien de requêtes il écarte. Seules les requêtes `GET` sont rejouées (un `POST` n'a pas de corps
  dans le log) ; une requête qui écrirait est refusée par le service faute de session ou de jeton.
- **Il s'arrête tout seul**, en laissant finir les requêtes en vol, dès que le temps de réponse médian des 20
  dernières requêtes atteint `--stop-latency` (3 s), ou que 20 % des 50 dernières ont échoué, ou que
  `--max-inflight` (100) requêtes attendent une réponse, ou que la page de sonde facultative
  (`--probe-url`, sinon `load_probe_url`) est lente. Il demande confirmation (`--yes` pour l'éviter) et
  affiche d'abord le plan.
- **Les requêtes s'ajoutent au trafic réel** : choisis une heure creuse. Mets l'IP de la machine qui rejoue
  dans la liste welcome, sinon fobots la bannit. Rejouer depuis une autre machine que le serveur évite de lui
  prendre CPU et mémoire.
- **Le rapport** donne, pour chaque palier, les requêtes/s, le temps de réponse médian / p95 / max, les échecs
  et le temps de sonde le plus haut ; où le service a cédé ; et le **coût par type de requête** (les
  répertoires, comme dans `fobots analyse`) : le p95 du premier et du dernier palier.
- **Fidélité.** Le log garde le statut et la taille de chaque réponse. Le rapport les compare à ce que le
  serveur répond maintenant : une page refusée ou redirigée faute de session coûte moins que la vraie, la
  charge mesurée est alors une borne basse. Chaque requête au statut différent est comptée et les changements
  les plus fréquents (`200 -> 302`) sont listés. Les échecs sous la charge (`200 -> no answer`, 5xx) sont
  distingués : c'est le serveur qui cède, pas une différence de session. Le rejeu envoie
  `Accept-Encoding: gzip` comme la plupart des clients (le serveur paie la compression, et la taille reçue est
  celle du log) ; `--no-compression` le désactive.

Avec `probe --record` qui tourne sur le serveur pendant le rejeu, l'incident est complet : le temps de réponse
de chaque type de requête, et l'état de la machine (mémoire, swap, file d'accept, processus) à chaque palier.

## Un log par hôte : règles par cible

Un serveur bien configuré écrit **un log par hôte virtuel**. Chaque log devient une
*cible*, avec ses propres règles, dans `fobots.conf` :

```ini
[site:app]
log = /var/log/nginx/access.log
ignore_path = ^/(assets/|favicon\.ico|robots\.txt)

[site:vitrine]                       # site entièrement statique
log = /var/log/nginx/vitrine.access.log
ignore_all = yes

[site:api]                           # aucune règle propre : tout est compté
log = /var/log/nginx/api.access.log
```
- `log` (obligatoire), `ignore_path` (regex sur le chemin), `ignore_all` (rien n'est compté pour cette cible), `watch_agent` / `watch_path` (surveillance, voir plus bas ; remplacent celles de `[fobots]` pour cette cible), `trap_ignore` (chemins qui ne sont jamais des pièges, voir plus bas ; remplace celle de `[fobots]`).
- Les règles propres **s'ajoutent** à l'`ignore_path` global de `[fobots]`.
- Les alias CNAME d'un hôte n'ont aucun effet : ils aboutissent dans le même log, donc
  dans la même cible. Le nom d'hôte n'est jamais lu dans les lignes.
- Le **comptage reste global par plage d'IP** : les requêtes de toutes les cibles
  s'additionnent, puisque le pare-feu bannit une plage pour tous les hôtes (ports 80/443).
- Un thread suit chaque log (rotation gérée) ; les formats peuvent différer d'un log à
  l'autre (il faut l'IP, l'horodatage et la ligne de requête).
- Le `log` unique de `[fobots]` fonctionne toujours (cible « default » sans règle propre),
  mais ne peut pas désigner le même fichier qu'une section `[site:…]`.
- Des fichiers donnés en argument (`run fichier.log`) sont lus une fois, sans suivre les
  cibles ; seule la règle globale s'applique.
- `SIGUSR1` affiche, par cible, les lignes lues et exclues : pratique pour vérifier qu'une
  règle fait ce qu'on attend. `install` donne au service l'accès à tous les logs.

## Pages statiques : ne pas les compter

Opt-in : `ignore_path` (regex sur le chemin de la requête, global ou par cible) retire du
comptage les requêtes correspondantes. Elles ne comptent ni pour le seuil d'une plage ni pour le déclenchement
de RDAP, et ne sont pas non plus notées par `watch_*`.

```
ignore_path = ^/(assets/|favicon|robots\.txt)
```
**Pourquoi :** un seul chargement de page déclenche des dizaines de requêtes
d'assets dans la même seconde. Compter ces requêtes gonfle le débit des visiteurs
légitimes et favorise les faux positifs. Une fois les statiques exclues, le seuil
mesure surtout les requêtes coûteuses, et on peut le baisser. Le chemin lu est celui de
la ligne de requête (`GET /chemin?…`) : cela marche aussi avec le format *common*.

**Prudence :**
- N'exclure que ce qui est **peu coûteux à servir**. Ancrer sur des **préfixes** de
  répertoires statiques (`^/assets/`), pas sur des extensions : `\.js$` ou `\.css$`
  exempteraient aussi les fichiers du dépôt (`/-/raw/…/x.js`, `/-/blob/…`), dynamiques et
  coûteux, que des scrapers adorent.
- Un scraper qui ne demande que des chemins exclus n'est jamais banni (ce qui est voulu :
  c'est peu coûteux), et les lignes dont la requête est illisible sont comptées.
- **Ce n'est pas une autorisation d'accès.** Une plage bannie est rejetée par le
  pare-feu *avant* nginx, qui ne voit pas les chemins : elle n'atteint donc pas non plus
  les pages statiques. Servir quelque chose aux plages bannies demanderait de les rediriger
  vers un autre serveur plutôt que de les rejeter.

## Analyser un log : `fobots analyse`

```
fobots analyse                      # les logs de fobots.conf
fobots analyse access.log -t 3      # un fichier donné, avec le seuil 3 mis en avant
```
Lit les logs une fois (ni nft, ni démon, ni requête RDAP : seulement les plages déjà dans le
cache) et affiche :

- le **tableau « et si »** : pour plusieurs seuils, combien de plages auraient été bannies
  (au-dessus du seuil pendant `sustain` secondes consécutives) et quelle part des requêtes
  elles ont envoyée, puis les plages les plus actives. Choisis le seuil à partir duquel le
  tableau cesse de grossir ;
- les **scrapers lents** : débit moyen de chaque plage sur `--slow-window` (10 min par défaut).
  Un scraper qui reste à environ une requête par seconde pendant des heures ne dépasse jamais
  un seuil par seconde, et peut pourtant peser la moitié du trafic ; ce tableau dit combien de
  plages se comportent ainsi ;
- les **répertoires** les plus demandés, la part de fichiers statiques, ce que ton
  `ignore_path` exclut déjà, et un `ignore_path` suggéré (répertoires fréquents qui ne servent
  presque que du statique, et rapides quand le log a les durées) ;
- les user-agents les plus fréquents, avec le nombre d'IP et de plages sur lesquelles ils sont
  répartis : un même agent qui fait une grande part du trafic sur beaucoup de plages est un
  scraper distribué.

**Durée des requêtes.** Elle n'est pas dans les formats usuels. Pour classer les répertoires
par coût et éviter d'exclure quelque chose de lent, ajoute-la en **dernier** champ : Apache
`LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %D" combined`
(microsecondes), nginx `$request_time` (secondes). `--time-unit` force l'unité (auto : un
nombre décimal est en secondes, un entier en microsecondes). Le démon n'est pas gêné par ce
champ supplémentaire.

Ce sont des **suggestions** : rien n'est modifié, et une suggestion tirée d'une journée
calme se vérifie avant usage.

## Chemins pièges : ce que seuls les scanners demandent (`traps`)

Un chemin qui reçoit un 404 ou un 403 et que demandent beaucoup d'IP distinctes de réseaux
différents (par défaut : 5 IP de 3 réseaux /16 en 6 h) est un piège : `/.env`, `/wp-login.php`
sur un site qui n'est pas WordPress… On compte des IP et non des requêtes : un seul client qui
boucle sur un lien mort n'en fabrique pas.

Ce que le site sert réellement protège des faux positifs :

- un chemin qui a répondu une fois (2xx, 3xx, 401, 405) n'est jamais un piège ;
- un chemin de la même **forme** non plus. Les segments variables sont remplacés par un type
  fixe (`{uuid}`, `{int}`, `{ulid}`, `{hex}`, `{slug}`) : un `/post/<uuid>` supprimé n'est pas pris
  pour un scan dès que le site a servi `/post/{uuid}` avec `trap_template_min` (3) valeurs
  différentes. Un segment avec `..`, `%`, `.env`, `.git`, `wp-admin`… ne correspond jamais à un
  type, et un slug doit contenir un chiffre ;
- `/favicon.ico`, `/robots.txt`, `/sitemap*.xml`, `/apple-touch-icon*`, `/.well-known/…` et
  quelques fichiers semblables ne sont jamais des pièges : tout navigateur ou robot les demande,
  qu'ils existent ou non ;
- `trap_ignore` (regex, globale ou dans une section `[site:NOM]`, qui la remplace) ajoute des
  chemins qui ne sont jamais des pièges.

**Deuxième signal : un scan.** Un scanner qui parcourt un dictionnaire demande des dizaines de
chemins *différents*, sous de nombreux répertoires différents, et n'obtient presque aucune
réponse : `/wp-json`, `/owa`, `/geoserver`, `/vendor/phpunit/…`, `/login.cgi`. Sa vitesse ne
compte pas (une requête toutes les deux secondes, ou trente en une seconde), seulement cette
dispersion. Une IP qui demande `trap_scan_paths` (20) chemins inexistants différents, sous au
moins `trap_scan_segments` (5) répertoires de tête différents, en `trap_scan_window` (5 min),
avec au plus une requête sur dix répondue, est signalée aussitôt, dès le premier scanner
(inutile que d'autres IP aient demandé les mêmes chemins). Les autres trafics ont une autre
allure : une page aux assets cassés se concentre sur un ou deux répertoires et son HTML a reçu
une réponse ; un visiteur au lien mort demande un seul chemin. Les requêtes qui ne sont jamais
des pièges (favicon…, formes servies par le site, `trap_ignore`) et la liste welcome des pièges
ne comptent pas. `trap_scan_paths = 0` désactive.

**Réaction.** Une IP qui a demandé `trap_hits` (2) pièges distincts est signalée, y compris
celles qui ont fabriqué les pièges. Le signal est individuel, le ban aussi : l'IP seule (IPv6 :
son /64), jamais son allocation RDAP, pendant `trap_ban_time` (1 h), doublé à chaque retour
(7 j au plus). **Une IP, pas son réseau.** Une requête sur un piège renseigne sur une machine, la sanction est
donc individuelle : une machine d'un réseau autorisé qui scanne est bannie seule et le reste du
réseau reste joignable. En IPv6 l'unité est le /64, car un scanner change d'adresse à volonté à
l'intérieur ; une IP de la liste welcome des pièges située dans ce /64 est exclue du ban. Les
bans de débit sont l'inverse, volontairement : leur raison d'être est une charge répartie sur
beaucoup d'IP d'une plage, que le ban par IP ne verrait pas (`ban_scope = observed` les restreint
aux groupes d'IP réellement vus).

**`welcome.txt` ne protège pas des pièges** : elle contient des réseaux de confiance, souvent internes, et les attaques viennent aussi de l'intérieur. Les pièges ont leur propre liste, `trap_welcome.txt` à côté de la configuration (`trap_welcome` pour la déplacer) : ses IP ne fabriquent pas de piège et ne sont jamais signalées. À réserver aux scanners de sécurité que l'on accepte (audit, supervision, test d'intrusion) :

```
fobots welcome add --traps 198.51.100.0/24   # lève aussi les bans de cette plage
fobots welcome list --traps
```
`fobots traps` affiche cette commande pour les IP signalées.

Ce qui a été appris (chemins et formes servis, candidats, IP signalées et récidivistes) est
enregistré dans `traps.json` toutes les 5 minutes de temps de log et à l'arrêt du démon, puis
relu au démarrage : redémarrer le service n'oublie rien. Supprimer le fichier pour repartir de zéro. Tant que `trap_ban = yes` n'est pas posé, une IP
signalée est seulement journalisée (`TRAP … would be banned`) et listée par `fobots traps` :
**commencer par là** et lire la liste sur son propre trafic.

```
traps = yes          # dans [fobots] : le démon apprend, par cible, et écrit <dir>/traps.json
trap_ban = no        # yes : bannit les IP signalées (sinon, journal seulement)
fobots traps         # pièges, formes et IP signalées, d'après l'instantané du démon
fobots traps access.log autre.log   # idem, calculé maintenant depuis des logs (ni nft, ni root)
```
Options : `trap_min_ips`, `trap_min_nets`, `trap_window`, `trap_template_min`, `trap_hits`,
`trap_scan_paths`, `trap_scan_segments`, `trap_scan_window`, `trap_ban_time`, `trap_ignore`, `trap_welcome`, `traps_file`. Un robot d'indexation qui suit des liens morts
depuis plusieurs réseaux ressemble à un scanner (le mettre dans la liste welcome ou dans
`trap_ignore`). Pas encore couvert : un site qui répond 200 à tout, et un scanner qui reste sous les
seuils du scan (moins de 20 chemins en 5 minutes, ou mêlés de requêtes répondues).

## Repérer des IP légitimes prises dans un ban (runners CI…)

Opt-in : `watch_agent` (regex sur l'user-agent) et `watch_path` (regex sur la route) ;
si les deux sont donnés, les deux doivent correspondre. La route dépend de l'hôte : elles se
placent dans la section `[site:NOM]` de cet hôte (une valeur de `[fobots]` s'applique aux
cibles qui n'en ont pas). Exemple pour les runners :

```
[site:app]
log = /var/log/nginx/access.log
watch_agent = ^ci-runner
watch_path  = ^/api/
```
Ces requêtes sont **comptées comme les autres** : aucune exemption, donc rien à
usurper. Quand une plage est bannie, le démon note les IP qui correspondaient, dans
le journal (ligne `WATCH`) **et** dans `<dir>/watched.jsonl` (un constat par ban,
élagué au-delà de 30 jours au démarrage). La commande relit ce fichier, sans
journalctl, et l'associe à l'état actuel des bans dans nft :

```
fobots watched                 # 7 derniers jours (--since 12h, 3d…)
fobots watched --active        # seulement celles dont le ban est actif
fobots watched --cmd           # n'affiche que la commande welcome add
```
```
IP          BANS  REQ  LAST BAN          RANGE        STATE          ROUTE
40.2.2.2       1    2  2026-10-10 13:40  40.0.0.0/12  active (1234 s) /api/jobs/7/artifacts
20.1.1.1       2    6  2026-10-10 13:40  20.0.0.0/12  expired        /api/jobs/request

To protect them all:
  fobots welcome add 40.2.2.2/32 20.1.1.1/32
```
Les IP sont agrégées sur la période : *BANS* = nombre de bans où elles ont été prises
(une IP prise plusieurs fois est un suspect sérieux). Les bans expirant vite, c'est
l'historique du fichier qui permet de les voir au retour d'une absence. L'état
« active/expired » (colonne STATE) demande l'accès à nft (sinon `?`). Rien n'est ajouté automatiquement
à la liste welcome.

Limites : seules les requêtes vues dans l'heure avant le ban sont notées (5 000 IP
gardées au plus, 200 par constat) ; les IP privées ne sont jamais comptées ; les lignes
dont l'agent ne se lit pas (autre format de log) ne sont pas surveillées. Les
`git clone` des jobs portent en général l'agent `git/…` : pour les voir,
`watch_agent = ^(ci-runner|git/)`.

## Emplacements des fichiers

Les chemins par défaut sont absolus : le résultat ne dépend jamais du dossier d'où l'on
lance une commande, et le démon, `welcome`, `bans` et `watched` voient les mêmes fichiers.

| Quoi | Où | Pourquoi |
|---|---|---|
| Configuration, liste welcome | `/etc/fobots/` | décidées par l'administrateur ; le démon ne fait que les lire |
| Cache RDAP, constats surveillés | `/var/lib/fobots/` | état écrit par le démon (créé s'il manque, mode 0750) |
| Journaux | journald (`journalctl -u fobots`) | aucun fichier |
| Commande | `/usr/local/sbin/fobots` (paquet : `/usr/sbin/fobots`) | le lanceur, installé sans `.py` |
| Modules | `/opt/fobots/fobots/` | le paquet `fobots/`, trouvé par la commande |

**Droits :** le démon peut tourner sous un utilisateur dédié avec la seule capacité
`CAP_NET_ADMIN` (voir `fobots.service.example`). Les commandes d'administration
(`setup`, `bans`, `watched`, `welcome add`) doivent s'exécuter **en root (`sudo`)** :
elles lisent ou modifient nft, et `welcome add` écrit dans `/etc/fobots/`.

## Configuration

`fobots.conf` (section `[fobots]`), cherché d'abord dans `/etc/fobots/`, puis dans le
dossier courant (pratique pour le développement : seulement si le fichier appartient à
l'utilisateur qui lance la commande et que personne d'autre ne peut le modifier, ni lui ni son
dossier ; avec `sudo` dans votre propre clone, donnez-le par `-f`), ou donné par `-f`. Les chemins
relatifs y sont relatifs au fichier de conf. **La ligne de commande l'emporte sur la
conf.** Voir `fobots.conf.example` pour toutes les clés :

| Clé | Défaut | Rôle |
|---|---|---|
| `log` | aucun | log suivi en continu (rotation gérée) ; voir aussi les sections `[site:NOM]` |
| `dir` | `/var/lib/fobots` | dossier d'état : `ip_ranges.json`, `watched.jsonl` (créé s'il manque) |
| `cache` | `<dir>/ip_ranges.json` | cache des plages RDAP |
| `welcome` | `welcome.txt` à côté de la conf utilisée, sinon `/etc/fobots/` | plages à ne jamais bannir |
| `threshold` | 5 | req/s d'une plage au-delà desquelles on bannit |
| `prefix_threshold` | = `threshold` | req/s d'un `/16` non résolu qui autorisent RDAP |
| `sustain`, `window` | 5, 60 | secondes consécutives au-dessus du seuil exigées ; fenêtre de suivi (s) |
| `traps`, `trap_ban` | non, non | apprend les chemins pièges (404/403 demandés par beaucoup d'IP) et signale les IP qui en demandent `trap_hits` ; avec `trap_ban` elles sont bannies, sinon seulement journalisées ; voir `fobots traps` |
| `trap_hits`, `trap_scan_paths`, `trap_scan_segments`, `trap_scan_window`, `trap_ban_time`, `trap_min_ips`, `trap_min_nets`, `trap_window`, `trap_template_min`, `trap_ignore`, `trap_welcome`, `traps_file` | 2, 20, 5, 5m, 1h, 5, 3, 6h, 3, aucun, `trap_welcome.txt` à côté de la configuration, `<dir>/traps.json` | réglages de ce qui précède |
| `slow_threshold`, `slow_window` | 0, 10m | bannit une plage dont le débit **moyen** sur la fenêtre dépasse cette valeur (req/s) ; `0` = désactivé |
| `ban_time` | 1h | durée d'un ban (`30m`, `1h`, `1d`) |
| `ban_scope` | `observed` | `observed` : seulement les groupes d'IP vues dans la plage RDAP ; `allocation` : on bannit la plage entière |
| `observed_prefix` | 20 | `observed` : étendue maximale d'un groupe d'IP (préfixe IPv4 ; IPv6 : `/48`) |
| `observed_escalate` | 4 | `observed` : bans partiels d'une allocation, pendant la durée d'un ban, avant le repli en blocs larges |
| `observed_max_prefix` | 16 | `observed` : largeur des blocs bannis en repli (préfixe IPv4 ; IPv6 : `/32`) ; `0` = allocation entière |
| `rdap_per_hour`, `delay` | 100, 2 | budget et espacement des requêtes RDAP |
| `load_signal` | `none` | durcissement selon la charge : `probe`, `psi`, `loadavg` ou `none` |
| `load_probe_url`, `load_probe_timeout` | aucun, 10s | signal `probe` : page(s) `[HOTE@]URL` demandée(s) ; une réponse plus lente compte pour la valeur du délai |
| `load_tense`, `load_critical` | 20 / 50 (psi), 1.0 / 2.0 (loadavg) | paliers du signal |
| `load_recover` | 5m | durée sous le palier avant de redescendre d'un niveau |
| `tense_factor`, `critical_factor` | 0.5, 0.25 | multiplicateur du seuil **et** de la durée de ban |
| `min_threshold`, `min_ban_time` | 1, 1m | planchers du seuil et de la durée effectifs |
| `from_start` | non | lire d'abord le contenu existant du log |

Sans `log` ni section `[site:…]`, le démon **refuse de démarrer** (erreur claire), sauf si
stdin est un tube ou un fichier (`tail -F fichier | fobots run`) ou si `-` est passé
explicitement. Des fichiers passés en argument sont lus une fois (`-` = stdin), ce qui sert
à rejouer un log.

Si le démon ne suit rien alors que la conf semble correcte, vérifier qu'il lit bien
la conf attendue (la ligne `configuration: …` au démarrage) et que le script installé
est à jour : une ancienne copie ignore les sections `[site:…]` sans le dire. `SIGUSR1`
indique aussi le nombre de lignes illisibles (format de log inattendu, par ex. le préfixe
`hôte:port` du format Apache `vhost_combined`, non géré).

## Commandes

```
fobots run [-t SEUIL] [-p SEUIL_PREFIXE] [--log FICHIER] [fichiers…]   (sans argument : suit les logs de la conf)
fobots install [--dry-run] [--log F] installe nftables, l'utilisateur, la conf, l'unité systemd
fobots setup                      crée la table, les sets et les règles nft
fobots bans [--no-lookup]          bans actifs, temps restant et organisation (nom + contact abuse RDAP, cherchés puis mis en cache si absents)
fobots welcome add CIDR…        liste welcome + retrait des bans concernés
fobots welcome list
fobots watched [--active] [--cmd]  IP surveillées (watch_*) prises dans un ban
fobots traps [LOG…]            chemins pièges (404/403 demandés par beaucoup d'IP), appris par le démon ou depuis des logs
fobots analyse [LOG…]           lit des logs une fois et suggère des réglages (sans nft ni root)
```
Options communes : `-f CONF`, `--dir`, `-c`, `-w`, `--ban-time`, `--nft-bin`,
`--dry-run`, `-v`. `--dry-run` n'appelle pas nft : il affiche les commandes et
simule les sets en mémoire.

## Liste welcome

```
fobots welcome add 17.0.0.0/8 -f /etc/fobots/fobots.conf
```
La plage est ajoutée à `welcome.txt` (le démon cesse aussitôt de la bannir : il
relit le fichier avant chaque ban), puis les bans qui la touchent sont retirés.
Si la plage est incluse dans un ban plus large, le reste est remis avec son temps
restant (`17.1.0.0/16` dans `17.0.0.0/8` donne 8 morceaux autour du `/16`).
Une plage bannie qui recoupe la liste welcome l'est sans la partie protégée.

## Remise à zéro

```
nft flush set inet fobots banned4        # et banned6 : tous les bans, immédiat
nft list set inet fobots banned4         # voir ce qui est banni
nft delete element inet fobots banned4 { 47.74.0.0/15 }
nft delete table inet fobots             # tout retirer (refaire `setup`)
```
Le cache RDAP (`ip_ranges.json`) est indépendant : le supprimer force à refaire
les requêtes RDAP, rien de plus.

## Rotation des logs

Le suivi du log fonctionne comme `tail -F` : renommage (`create`), troncature
(`copytruncate`) et absence temporaire du fichier sont gérés, sans signal à
envoyer. Après un renommage, l'ancien fichier est encore lu 2 s (le serveur y
écrit jusqu'à la réouverture). Avec `copytruncate`, les lignes écrites entre la
copie et la troncature sont perdues (limite de logrotate). Chaque log
(sections `[site:…]` ou `log` de `[fobots]`) est suivi indépendamment, donc chacun peut
avoir sa propre rotation.

## Signaux et journal

Les journaux vont sur stderr (journal systemd sous service). Chaque ban indique
la plage, le débit, l'IP déclenchante et le total de requêtes. `SIGUSR1` affiche
les plages les plus actives depuis le démarrage ; `SIGTERM`/`SIGINT` arrêtent.

## Scrapers lents (`slow_threshold`)

Un scraper qui reste à environ une requête par seconde, réparti sur de nombreuses IP d'une
allocation cloud, ne dépasse jamais un `threshold` par seconde. Avec `slow_threshold = 0.5` et
`slow_window = 10m`, une plage est bannie quand elle a envoyé plus de 0,5 × 600 = 300 requêtes
sur les 10 dernières minutes (comptées par tranches de 10 secondes : pas de coût par requête).
Désactivé par défaut. À mesurer d'abord avec `fobots analyse` (tableau « Slow scrapers ») : il
montre quelles plages seraient prises et quelle part du trafic elles envoient. Pour le reste la
règle est la même que celle par seconde (liste `welcome`, `ban_scope`, `ban_time`) ; avec
`ban_scope = observed`, les IP vues sur toute la fenêtre sont considérées, donc le ban reste
serré. Attention : un gros réseau légitime (campus derrière un NAT) sur un site très fréquenté
peut dépasser un débit moyen bas ; vérifie avec `analyse` sur tes propres logs, et corrige les
faux positifs avec `welcome add`. Il n'est pas modulé par le niveau de charge.

## Ban resserré (`ban_scope = observed`)

C'est le défaut. Avec `ban_scope = allocation`, toute l'allocation est bannie : un seul client
au-dessus du seuil coupe alors tous les visiteurs de son fournisseur (jusqu'à un `/8`). RDAP continue de
fournir la **frontière** (l'allocation) et de décider *quand* bannir (même seuil, même
comptage par allocation). Ce qui change, c'est *quoi* : au lieu de l'allocation entière,
on bannit les IP vues pendant la fenêtre `window`, regroupées ainsi :

- les IP sont triées et regroupées tant que l'étendue du groupe reste sous
  `observed_prefix` (4096 adresses par défaut) ; un groupe est borné par ses IP extrêmes
  (un intervalle, pas un CIDR : deux IP voisines de part et d'autre d'une frontière de
  bloc restent ensemble) ;
- on bannit les groupes les plus actifs jusqu'à couvrir 80 % des requêtes de l'allocation ;
  les IP isolées qui restent (visiteurs légitimes) ne sont pas touchées ;
- **repli en blocs larges** si le trafic est trop dispersé (plus de 4 groupes nécessaires),
  ou après `observed_escalate` bans partiels de la même allocation pendant la durée d'un
  ban (le scraper change de plage). On bannit alors les blocs de `observed_max_prefix`
  (`/16` par défaut) qui portent 80 % des requêtes, **jamais plus larges**, même si
  l'allocation est un `/10` : une allocation Google Cloud donne quelques `/16`, pas un
  `/10`. Une allocation plus étroite que le bloc est bannie telle quelle ; avec
  `observed_max_prefix = 0`, le repli bannit l'allocation entière.

Le journal indique pour chaque ban le nombre d'IP, de groupes et la part des requêtes
couverte. Pour comparer sans risque : `run --dry-run --ban-scope observed` sur un même log
rejoué (`fobots run --dry-run --ban-scope allocation LOG`, puis `observed`).
Quand un ban en remplace d'autres (un `/16` qui englobe des `/32`), le démon retire les
anciens éléments puis ajoute le nouveau en **deux transactions** nft : nft 0.9.x refuse de
le faire en une seule (« interval overlaps with an existing one »). Si l'ajout échoue, les
éléments retirés sont remis.
Mémoire : au plus 200 000 IP suivies. Les IPv4 et IPv6 sont traitées de la même façon.

## Limites connues

- **Temps de ban restant avec un vieux nftables.** Avec nftables 0.9.x, `nft list set`
  n'affiche que `timeout 1h` et jamais `expires` : `bans` et `watched` n'indiquent alors pas le
  temps restant. Les versions plus récentes affichent `expires`, que ces commandes utilisent.
- **Plage = allocation RIR** avec `ban_scope = allocation` (le défaut, `observed`, la resserre), souvent très large (`17.0.0.0/8`, `43.0.0.0/9`,
  `36.128.0.0/10`). Un ban frappe toute l'allocation, y compris des visiteurs
  légitimes. Garde-fou : le ban expire, la liste welcome corrige. Les réponses
  RDAP plus larges que `/8` (IPv4) ou `/16` (IPv6) sont rejetées.
- **Détection sur le log**, donc *après* la requête : nginx n'écrit une ligne
  qu'une fois la réponse terminée. Un serveur déjà saturé écrit ses logs en
  retard, et la réaction l'est aussi.
- **Compte toutes les requêtes** de la même façon, sans tenir compte de leur coût.
- **Pas d'escalade** : un scraper banni revient à l'expiration avec la même durée.
  Pas de réponse HTTP 429 préalable, pas de durée croissante.
- **Pas de disjoncteur** : aucun plafond sur le nombre ou la taille des bans (choix
  assumé : la liste welcome sert de rattrapage). Avec le durcissement par la charge,
  les seuils peuvent descendre jusqu'à `min_threshold` : surveiller les premiers jours.
- Les plages RDAP non résolues (budget épuisé, échec réseau) ne sont jamais
  bannies ; l'échec est journalisé et retenté plus tard.
- `nftables.service` avec `flush ruleset` efface la table `fobots` à chaque
  rechargement (voir les commentaires de `fobots.service.example`).

## Fichiers

| Fichier | Rôle |
|---|---|
| `fobots.py` | lanceur : `./fobots.py` dans un clone, installé comme la commande `fobots` |
| `fobots/` | le paquet : `cli` (commandes), `detector`, `nft`, `welcome` (bans), `rdap`, `grouping`, `follow` (logs), `load`, `sites`, `events`, `config`, `install`, `util`, `constants` |
| `fobots.conf.example` | configuration d'exemple |
| `fobots.service.example` | unité systemd d'exemple |
| `build-deb.sh`, `Makefile` | paquet Debian, `make test` |
| `tests/test_fobots.py` | tests unitaires |
| `tests/integration.sh` | test d'intégration (vrai nft, logs fictifs) |
| `/etc/fobots/fobots.conf` | configuration |
| `/etc/fobots/welcome.txt` | plages à ne jamais bannir, un CIDR par ligne (créé par `welcome add`) |
| `/var/lib/fobots/ip_ranges.json` | cache des plages RDAP |
| `/var/lib/fobots/traps.json` | instantané des chemins pièges appris (si `traps = yes`) |
| `/var/lib/fobots/watched.jsonl` | constats « IP surveillée prise dans un ban » (si `watch_*`) |

## Licence

fobots est un logiciel libre, distribué sous licence GNU GPL version 3 ou ultérieure
(`GPL-3.0-or-later`). Copyright (C) 2026 Joël Maizi. Voir le fichier `LICENSE`.
