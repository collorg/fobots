# fobots

Démon qui protège un serveur web (pensé pour un GitLab derrière nginx) des
scrapers trop agressifs. Il suit l'access log, repère les **plages d'IP** dont le
débit dépasse un seuil, et les ajoute à un set **nftables** avec expiration : le
trafic est rejeté par le pare-feu avant d'atteindre nginx et GitLab.

Python 3.7+ standard (aucune dépendance), nftables, Linux. Sur Ubuntu 20.04 (Python 3.8,
noyau 5.4) : `apt install nftables` (version 0.9.3).

> État : le bannissement a été validé en production sur Ubuntu 20.04 (Python 3.8, noyau
> 5.4, nftables 0.9.3) : charge de plus de 35 ramenée à 0,2. Les autres fonctions
> (unité systemd d'exemple, durcissement selon la charge, IPv6, surveillance
> `watch_*`) n'ont été testées qu'avec un faux `nft`. Avec nftables 0.9.3
> (Ubuntu 20.04), `nft list set` n'affiche que `timeout 1h` et jamais `expires` : `bans` et
> `watched` n'indiquent donc pas le temps restant. Sur des versions plus récentes (Ubuntu 24.04,
> d'après un retour d'usage), `expires` est affiché et repris par ces commandes.
> Commencer par `--dry-run`.

## Fonctionnement

1. Chaque ligne du log (format *combined* nginx/Apache/GitLab) est rattachée à
   une plage d'IP : celle de l'allocation RIR qui la contient (obtenue par RDAP,
   le successeur de whois). Le détail du propriétaire n'est pas conservé : seule
   la plage compte.
2. Les requêtes sont comptées par plage et par seconde. Quand une plage dépasse
   `threshold` req/s (pendant `sustain` secondes), elle est bannie pour
   `ban_time`.
3. Les plages inconnues ne sont pas interrogées au hasard : RDAP n'est appelé
   (en tâche de fond) que pour un préfixe `/16` (`/32` en IPv6) qui dépasse déjà
   `prefix_threshold` req/s, avec un budget horaire, un délai entre requêtes et
   une pause sur HTTP 429. Les plages trouvées sont enregistrées sur disque
   (`ip_ranges.json`) et réutilisées.
4. Par défaut le ban couvre **toute l'allocation**. Avec `ban_scope = observed`, il se
   resserre sur les IP réellement vues : voir « Ban resserré » plus bas.
5. Le ban est une transaction nft unique. Une plage déjà couverte par un ban plus
   large est ignorée ; une plage qui en englobe d'autres les remplace.
6. L'état des bans est **dans nft** (lu au démarrage) : le démon peut être
   relancé sans perte, et chaque ban expire seul.

## Installation

Sur Debian/Ubuntu, depuis un clone du dépôt :

```
sudo ./fobots.py install --dry-run            # le plan, sans rien modifier
sudo ./fobots.py install --log /var/log/gitlab/nginx/gitlab_access.log
```
La commande est **idempotente** (on peut la relancer pour mettre à jour le programme et
l'unité) et ne touche jamais une conf ou une liste welcome existantes. Elle :

1. vérifie Python (3.7+) et installe `nftables` avec apt-get si `nft` manque (demande
   confirmation, ou `--yes`) ;
2. **teste nft** sur une table jetable : sets d'intervalles avec expiration, sortie JSON
   lisible (s'arrête avec un message sinon) ; signale si cette version n'indique pas le
   temps restant des bans ;
3. crée l'utilisateur système `fobots` s'il manque ;
4. installe le programme dans `/opt/fobots/`, la conf dans `/etc/fobots/fobots.conf` (avec
   `--log` s'il est donné), une liste welcome vide `/etc/fobots/welcome.txt`, le dossier
   d'état `/var/lib/fobots` (0750, propriété de `fobots`) ;
5. installe l'unité systemd, avec le groupe qui donne accès au log (détecté, sinon `adm` ;
   `--log-group` pour l'imposer), puis `systemctl daemon-reload` ;
6. vérifie que l'utilisateur `fobots` peut lire le log, et dit quoi faire sinon.

Le service n'est **ni activé ni démarré** par défaut : adapter la conf, remplir la liste
welcome, essayer `/opt/fobots/fobots.py run --dry-run`, puis `systemctl enable --now fobots`
(ou relancer `install` avec `--enable` / `--start`). `--destdir DIR` écrit les fichiers sous
un préfixe sans toucher au système (tests, empaquetage).

À la main, sans `install` :

```
./fobots.py setup                          # crée la table nft (idempotent)
cp fobots.conf.example fobots.conf         # puis adapter log, seuils
./fobots.py run --dry-run -v               # affiche les bans sans toucher à nft
./fobots.py run                            # le vrai démon
```

Pour un service permanent, voir `fobots.service.example` (utilisateur dédié,
`CAP_NET_ADMIN` seulement, durcissement systemd).

Commencer prudemment : `ban_time = 10m`, un seuil qui ne vise que les cas
évidents, et garder une session ouverte (voir « Remise à zéro »).

## Durcissement selon la charge

Désactivé par défaut (`load_signal = none`). Quand il est actif, un thread mesure
la charge toutes les 5 s :

- `psi` : pression `/proc/pressure` (max de cpu et io, `some avg10`, en %), très
  réactive ; repli automatique sur `loadavg` si le noyau ne l'offre pas ;
- `loadavg` : charge sur 1 minute divisée par le nombre de cœurs (plus lente).

Trois niveaux : *normal*, *tendu*, *critique*. On y monte immédiatement ; on
redescend d'un niveau seulement après `load_recover` continu sous le palier. À
chaque niveau, **le seuil et la durée de ban sont multipliés** par le facteur
(0.5 puis 0.25 par défaut), sans descendre sous `min_threshold` / `min_ban_time` :
des règles plus sévères mais des bans plus courts, donc des plages rejugées plus
vite. `prefix_threshold` suit le même facteur. Exemple (base 10 req/s, 1 h) :
tendu = 5 req/s pendant 30 min, critique = 2,5 req/s pendant 15 min.

Les paliers par défaut ne sont **pas calibrés** sur ton serveur : lance d'abord
avec `--dry-run -v` et regarde les lignes `charge : psi=…` (toutes les 5 minutes et
à chaque changement de niveau) pour choisir `load_tense` / `load_critical`.
Les faux positifs se corrigent avec `welcome add`.

## Un log par hôte : règles par cible

Un serveur bien configuré écrit **un log par hôte virtuel**. Chaque log devient une
*cible*, avec ses propres règles, dans `fobots.conf` :

```ini
[site:gitlab]
log = /var/log/gitlab/nginx/gitlab_access.log
ignore_prefix = /assets/, /favicon.ico, /robots.txt

[site:vitrine]                       # site entièrement statique
log = /var/log/nginx/vitrine.access.log
ignore_all = yes

[site:api]                           # aucune règle propre : tout est compté
log = /var/log/nginx/api.access.log
```
- `log` (obligatoire), `ignore_prefix` (préfixes de chemin, séparés par des virgules),
  `ignore_path` (regex), `ignore_all` (rien n'est compté pour cette cible).
- Les règles propres **s'ajoutent** à l'`ignore_path` global de `[fobots]`.
- Les alias CNAME d'un hôte n'ont aucun effet : ils aboutissent dans le même log, donc
  dans la même cible. Le nom d'hôte n'est jamais lu dans les lignes.
- Le **comptage reste global par plage d'IP** : les requêtes de toutes les cibles
  s'additionnent, puisque le pare-feu bannit une plage pour tous les hôtes (ports 80/443).
- Un thread suit chaque log (rotation gérée) ; les formats peuvent différer d'un log à
  l'autre (il faut l'IP, l'horodatage et la ligne de requête).
- Le `log` unique de `[fobots]` fonctionne toujours (cible « défaut » sans règle propre),
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
**Pourquoi :** un seul chargement de page GitLab déclenche des dizaines de requêtes
d'assets dans la même seconde. Compter ces requêtes gonfle le débit des visiteurs
légitimes et favorise les faux positifs. Une fois les statiques exclues, le seuil
mesure surtout les requêtes coûteuses, et on peut le baisser. Le chemin lu est celui de
la ligne de requête (`GET /chemin?…`) : cela marche aussi avec le format *common*.

**Prudence :**
- N'exclure que ce qui est **peu coûteux à servir**. Ancrer sur des **préfixes** de
  répertoires statiques (`/assets/`), pas sur des extensions : `\.js$` ou `\.css$`
  exempteraient aussi les fichiers du dépôt (`/-/raw/…/x.js`, `/-/blob/…`), dynamiques et
  coûteux, que des scrapers adorent.
- Un scraper qui ne demande que des chemins exclus n'est jamais banni (ce qui est voulu :
  c'est peu coûteux), et les lignes dont la requête est illisible sont comptées.
- **Ce n'est pas une autorisation d'accès.** Une plage bannie est rejetée par le
  pare-feu *avant* nginx, qui ne voit pas les chemins : elle n'atteint donc pas non plus
  les pages statiques. Servir quelque chose aux plages bannies demanderait de les rediriger
  vers un autre serveur plutôt que de les rejeter.

## Repérer des IP légitimes prises dans un ban (gitlab-runner…)

Opt-in : `watch_agent` (regex sur l'user-agent) et `watch_path` (regex sur la route) ;
si les deux sont donnés, les deux doivent correspondre. Exemple pour les runners :

```
watch_agent = ^gitlab-runner
watch_path  = ^/api/v4/
```
Ces requêtes sont **comptées comme les autres** : aucune exemption, donc rien à
usurper. Quand une plage est bannie, le démon note les IP qui correspondaient, dans
le journal (ligne `WATCH`) **et** dans `<dir>/watched.jsonl` (un constat par ban,
élagué au-delà de 30 jours au démarrage). La commande relit ce fichier, sans
journalctl, et l'associe à l'état actuel des bans dans nft :

```
fobots.py watched                 # 7 derniers jours (--since 12h, 3d…)
fobots.py watched --active        # seulement celles dont le ban est actif
fobots.py watched --cmd           # n'affiche que la commande welcome add
```
```
IP          BANS  REQ  DERNIER BAN       PLAGE        ÉTAT           ROUTE
40.2.2.2       1    2  2026-10-10 13:40  40.0.0.0/12  actif (1234 s) /api/v4/jobs/7/artifacts
20.1.1.1       2    6  2026-10-10 13:40  20.0.0.0/12  expiré         /api/v4/jobs/request

Pour toutes les protéger :
  fobots.py welcome add 40.2.2.2/32 20.1.1.1/32
```
Les IP sont agrégées sur la période : *BANS* = nombre de bans où elles ont été prises
(une IP prise plusieurs fois est un suspect sérieux). Les bans expirant vite, c'est
l'historique du fichier qui permet de les voir au retour d'une absence. L'état
« actif/expiré » demande l'accès à nft (sinon `?`). Rien n'est ajouté automatiquement
à la liste welcome.

Limites : seules les requêtes vues dans l'heure avant le ban sont notées (5 000 IP
gardées au plus, 200 par constat) ; les IP privées ne sont jamais comptées ; les lignes
dont l'agent ne se lit pas (autre format de log) ne sont pas surveillées. Les
`git clone` des jobs portent en général l'agent `git/…` : pour les voir,
`watch_agent = ^(gitlab-runner|git/)`.

## Emplacements des fichiers

Les chemins par défaut sont absolus : le résultat ne dépend jamais du dossier d'où l'on
lance une commande, et le démon, `welcome`, `bans` et `watched` voient les mêmes fichiers.

| Quoi | Où | Pourquoi |
|---|---|---|
| Configuration, liste welcome | `/etc/fobots/` | décidées par l'administrateur ; le démon ne fait que les lire |
| Cache RDAP, constats surveillés | `/var/lib/fobots/` | état écrit par le démon (créé s'il manque, mode 0750) |
| Journaux | journald (`journalctl -u fobots`) | aucun fichier |
| Programme | `/opt/fobots/` ou `/usr/local/sbin/` | installation locale |

**Droits :** le démon peut tourner sous un utilisateur dédié avec la seule capacité
`CAP_NET_ADMIN` (voir `fobots.service.example`). Les commandes d'administration
(`setup`, `bans`, `watched`, `welcome add`) doivent s'exécuter **en root (`sudo`)** :
elles lisent ou modifient nft, et `welcome add` écrit dans `/etc/fobots/`.

## Configuration

`fobots.conf` (section `[fobots]`), cherché d'abord dans `/etc/fobots/`, puis dans le
dossier courant (pratique pour le développement), ou donné par `-f`. Les chemins
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
| `sustain`, `window` | 1, 60 | secondes au-dessus du seuil exigées, dans la fenêtre |
| `ban_time` | 1h | durée d'un ban (`30m`, `1h`, `1d`) |
| `ban_scope` | `allocation` | `allocation` : on bannit la plage RDAP entière ; `observed` : seulement les groupes d'IP vues dedans |
| `observed_prefix` | 20 | `observed` : étendue maximale d'un groupe d'IP (préfixe IPv4 ; IPv6 : `/48`) |
| `observed_escalate` | 4 | `observed` : bans partiels d'une allocation, pendant la durée d'un ban, avant le repli en blocs larges |
| `observed_max_prefix` | 16 | `observed` : largeur des blocs bannis en repli (préfixe IPv4 ; IPv6 : `/32`) ; `0` = allocation entière |
| `rdap_per_hour`, `delay` | 100, 2 | budget et espacement des requêtes RDAP |
| `load_signal` | `none` | durcissement selon la charge : `psi`, `loadavg` ou `none` |
| `load_tense`, `load_critical` | 20 / 50 (psi), 1.0 / 2.0 (loadavg) | paliers du signal |
| `load_recover` | 5m | durée sous le palier avant de redescendre d'un niveau |
| `tense_factor`, `critical_factor` | 0.5, 0.25 | multiplicateur du seuil **et** de la durée de ban |
| `min_threshold`, `min_ban_time` | 1, 1m | planchers du seuil et de la durée effectifs |
| `from_start` | non | lire d'abord le contenu existant du log |

Sans `log` ni section `[site:…]`, le démon **refuse de démarrer** (erreur claire), sauf si
stdin est un tube ou un fichier (`tail -F fichier | fobots.py run`) ou si `-` est passé
explicitement. Des fichiers passés en argument sont lus une fois (`-` = stdin), ce qui sert
à rejouer un log.

Si le démon ne suit rien alors que la conf semble correcte, vérifier qu'il lit bien
la conf attendue (la ligne `configuration : …` au démarrage) et que le script installé
est à jour : une ancienne copie ignore les sections `[site:…]` sans le dire. `SIGUSR1`
indique aussi le nombre de lignes illisibles (format de log inattendu, par ex. le préfixe
`hôte:port` du format Apache `vhost_combined`, non géré).

## Commandes

```
fobots.py run [-t SEUIL] [-p SEUIL_PREFIXE] [--log FICHIER] [fichiers…]   (sans argument : suit les logs de la conf)
fobots.py install [--dry-run] [--log F] installe nftables, l'utilisateur, la conf, l'unité systemd
fobots.py setup                      crée la table, les sets et les règles nft
fobots.py bans                       bans actifs et temps restant
fobots.py welcome add CIDR…        liste welcome + retrait des bans concernés
fobots.py welcome list
fobots.py watched [--active] [--cmd]  IP surveillées (watch_*) prises dans un ban
```
Options communes : `-f CONF`, `--dir`, `-c`, `-w`, `--ban-time`, `--nft-bin`,
`--dry-run`, `-v`. `--dry-run` n'appelle pas nft : il affiche les commandes et
simule les sets en mémoire.

## Liste welcome

```
fobots.py welcome add 17.0.0.0/8 -f /etc/fobots/fobots.conf
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

## Ban resserré (`ban_scope = observed`)

Désactivé par défaut : le comportement reste celui décrit plus haut. RDAP continue de
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
rejoué (`fobots.py run --dry-run --ban-scope allocation LOG`, puis `observed`).
Quand un ban en remplace d'autres (un `/16` qui englobe des `/32`), le démon retire les
anciens éléments puis ajoute le nouveau en **deux transactions** nft : nft 0.9.x refuse de
le faire en une seule (« interval overlaps with an existing one »). Si l'ajout échoue, les
éléments retirés sont remis.
Mémoire : au plus 200 000 IP suivies. Les IPv4 et IPv6 sont traitées de la même façon.

## Limites connues

- **Plage = allocation RIR** par défaut (voir `ban_scope = observed` pour resserrer), souvent très large (`17.0.0.0/8`, `43.0.0.0/9`,
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
| `fobots.py` | le démon et ses commandes |
| `fobots.conf.example` | configuration d'exemple |
| `fobots.service.example` | unité systemd d'exemple |
| `/etc/fobots/fobots.conf` | configuration |
| `/etc/fobots/welcome.txt` | plages à ne jamais bannir, un CIDR par ligne (créé par `welcome add`) |
| `/var/lib/fobots/ip_ranges.json` | cache des plages RDAP |
| `/var/lib/fobots/watched.jsonl` | constats « IP surveillée prise dans un ban » (si `watch_*`) |
