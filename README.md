# banbot

Démon qui protège un serveur web (pensé pour un GitLab derrière nginx) des
scrapers trop agressifs. Il suit l'access log, repère les **plages d'IP** dont le
débit dépasse un seuil, et les ajoute à un set **nftables** avec expiration : le
trafic est rejeté par le pare-feu avant d'atteindre nginx et GitLab.

Python 3.7+ standard (aucune dépendance), nftables, Linux. Sur Ubuntu 20.04 (Python 3.8,
noyau 5.4) : `apt install nftables` (version 0.9.3).

> État : le bannissement a été validé en production sur Ubuntu 20.04 (Python 3.8, noyau
> 5.4, nftables 0.9.3) : charge de plus de 35 ramenée à 0,2. Les autres fonctions
> (unité systemd d'exemple, durcissement selon la charge, IPv6, surveillance
> `watch_*`) n'ont été testées qu'avec un faux `nft`. Observé avec nftables 0.9.3 :
> `bans` n'affiche pas le temps restant (la sortie JSON de nft ne semble pas le fournir ;
> à confirmer avec `nft list set inet banbot banned4`).
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
4. Le ban est une transaction nft unique. Une plage déjà couverte par un ban plus
   large est ignorée ; une plage qui en englobe d'autres les remplace.
5. L'état des bans est **dans nft** (lu au démarrage) : le démon peut être
   relancé sans perte, et chaque ban expire seul.

## Installation rapide

```
./banbot.py setup                          # crée la table nft (idempotent)
cp banbot.conf.example banbot.conf         # puis adapter log, dir, seuils
./banbot.py run --dry-run -v               # affiche les bans sans toucher à nft
./banbot.py run                            # le vrai démon
```

Pour un service permanent, voir `banbot.service.example` (utilisateur dédié,
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
Les faux positifs se corrigent avec `whitelist add`.

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
banbot.py watched                 # 7 derniers jours (--since 12h, 3d…)
banbot.py watched --active        # seulement celles dont le ban est actif
banbot.py watched --cmd           # n'affiche que la commande whitelist add
```
```
IP          BANS  REQ  DERNIER BAN       PLAGE        ÉTAT           ROUTE
40.2.2.2       1    2  2026-10-10 13:40  40.0.0.0/12  actif (1234 s) /api/v4/jobs/7/artifacts
20.1.1.1       2    6  2026-10-10 13:40  20.0.0.0/12  expiré         /api/v4/jobs/request

Pour toutes les protéger :
  banbot.py whitelist add 40.2.2.2/32 20.1.1.1/32
```
Les IP sont agrégées sur la période : *BANS* = nombre de bans où elles ont été prises
(une IP prise plusieurs fois est un suspect sérieux). Les bans expirant vite, c'est
l'historique du fichier qui permet de les voir au retour d'une absence. L'état
« actif/expiré » demande l'accès à nft (sinon `?`). Rien n'est ajouté automatiquement
à la liste blanche.

Limites : seules les requêtes vues dans l'heure avant le ban sont notées (5 000 IP
gardées au plus, 200 par constat) ; les IP privées ne sont jamais comptées ; les lignes
dont l'agent ne se lit pas (autre format de log) ne sont pas surveillées. Les
`git clone` des jobs portent en général l'agent `git/…` : pour les voir,
`watch_agent = ^(gitlab-runner|git/)`.

## Emplacements des fichiers

Les chemins par défaut sont absolus : le résultat ne dépend jamais du dossier d'où l'on
lance une commande, et le démon, `whitelist`, `bans` et `watched` voient les mêmes fichiers.

| Quoi | Où | Pourquoi |
|---|---|---|
| Configuration, liste blanche | `/etc/banbot/` | décidées par l'administrateur ; le démon ne fait que les lire |
| Cache RDAP, constats surveillés | `/var/lib/banbot/` | état écrit par le démon (créé s'il manque, mode 0750) |
| Journaux | journald (`journalctl -u banbot`) | aucun fichier |
| Programme | `/opt/banbot/` ou `/usr/local/sbin/` | installation locale |

**Droits :** le démon peut tourner sous un utilisateur dédié avec la seule capacité
`CAP_NET_ADMIN` (voir `banbot.service.example`). Les commandes d'administration
(`setup`, `bans`, `watched`, `whitelist add`) doivent s'exécuter **en root (`sudo`)** :
elles lisent ou modifient nft, et `whitelist add` écrit dans `/etc/banbot/`.

## Configuration

`banbot.conf` (section `[banbot]`), cherché d'abord dans `/etc/banbot/`, puis dans le
dossier courant (pratique pour le développement), ou donné par `-f`. Les chemins
relatifs y sont relatifs au fichier de conf. **La ligne de commande l'emporte sur la
conf.** Voir `banbot.conf.example` pour toutes les clés :

| Clé | Défaut | Rôle |
|---|---|---|
| `log` | stdin | log suivi en continu (rotation gérée) |
| `dir` | `/var/lib/banbot` | dossier d'état : `ip_ranges.json`, `watched.jsonl` (créé s'il manque) |
| `cache` | `<dir>/ip_ranges.json` | cache des plages RDAP |
| `whitelist` | `whitelist.txt` à côté de la conf utilisée, sinon `/etc/banbot/` | plages à ne jamais bannir |
| `threshold` | 5 | req/s d'une plage au-delà desquelles on bannit |
| `prefix_threshold` | = `threshold` | req/s d'un `/16` non résolu qui autorisent RDAP |
| `sustain`, `window` | 1, 60 | secondes au-dessus du seuil exigées, dans la fenêtre |
| `ban_time` | 1h | durée d'un ban (`30m`, `1h`, `1d`) |
| `rdap_per_hour`, `delay` | 100, 2 | budget et espacement des requêtes RDAP |
| `load_signal` | `none` | durcissement selon la charge : `psi`, `loadavg` ou `none` |
| `load_tense`, `load_critical` | 20 / 50 (psi), 1.0 / 2.0 (loadavg) | paliers du signal |
| `load_recover` | 5m | durée sous le palier avant de redescendre d'un niveau |
| `tense_factor`, `critical_factor` | 0.5, 0.25 | multiplicateur du seuil **et** de la durée de ban |
| `min_threshold`, `min_ban_time` | 1, 1m | planchers du seuil et de la durée effectifs |
| `from_start` | non | lire d'abord le contenu existant du log |

Sans `log`, le démon lit stdin (`tail -F fichier | banbot.py run`). Des fichiers
passés en argument sont lus une fois (`-` = stdin), ce qui sert à rejouer un log.

## Commandes

```
banbot.py run [-t SEUIL] [-p SEUIL_PREFIXE] [--log FICHIER] [fichiers…]
banbot.py setup                      crée la table, les sets et les règles nft
banbot.py bans                       bans actifs et temps restant
banbot.py whitelist add CIDR…        liste blanche + retrait des bans concernés
banbot.py whitelist list
banbot.py watched [--active] [--cmd]  IP surveillées (watch_*) prises dans un ban
```
Options communes : `-f CONF`, `--dir`, `-c`, `-w`, `--ban-time`, `--nft-bin`,
`--dry-run`, `-v`. `--dry-run` n'appelle pas nft : il affiche les commandes et
simule les sets en mémoire.

## Liste blanche

```
banbot.py whitelist add 17.0.0.0/8 -f /etc/banbot/banbot.conf
```
La plage est ajoutée à `whitelist.txt` (le démon cesse aussitôt de la bannir : il
relit le fichier avant chaque ban), puis les bans qui la touchent sont retirés.
Si la plage est incluse dans un ban plus large, le reste est remis avec son temps
restant (`17.1.0.0/16` dans `17.0.0.0/8` donne 8 morceaux autour du `/16`).
Une plage bannie qui recoupe la liste blanche l'est sans la partie protégée.

## Remise à zéro

```
nft flush set inet banbot banned4        # et banned6 : tous les bans, immédiat
nft list set inet banbot banned4         # voir ce qui est banni
nft delete element inet banbot banned4 { 47.74.0.0/15 }
nft delete table inet banbot             # tout retirer (refaire `setup`)
```
Le cache RDAP (`ip_ranges.json`) est indépendant : le supprimer force à refaire
les requêtes RDAP, rien de plus.

## Rotation des logs

Le suivi du log fonctionne comme `tail -F` : renommage (`create`), troncature
(`copytruncate`) et absence temporaire du fichier sont gérés, sans signal à
envoyer. Après un renommage, l'ancien fichier est encore lu 2 s (le serveur y
écrit jusqu'à la réouverture). Avec `copytruncate`, les lignes écrites entre la
copie et la troncature sont perdues (limite de logrotate). Un seul log est suivi
en interne ; pour plusieurs : `tail -F a b | banbot.py run`.

## Signaux et journal

Les journaux vont sur stderr (journal systemd sous service). Chaque ban indique
la plage, le débit, l'IP déclenchante et le total de requêtes. `SIGUSR1` affiche
les plages les plus actives depuis le démarrage ; `SIGTERM`/`SIGINT` arrêtent.

## Limites connues

- **Plage = allocation RIR**, souvent très large (`17.0.0.0/8`, `43.0.0.0/9`,
  `36.128.0.0/10`). Un ban frappe toute l'allocation, y compris des visiteurs
  légitimes. Garde-fou : le ban expire, la liste blanche corrige. Les réponses
  RDAP plus larges que `/8` (IPv4) ou `/16` (IPv6) sont rejetées.
- **Détection sur le log**, donc *après* la requête : nginx n'écrit une ligne
  qu'une fois la réponse terminée. Un serveur déjà saturé écrit ses logs en
  retard, et la réaction l'est aussi.
- **Compte toutes les requêtes** de la même façon, sans tenir compte de leur coût.
- **Pas d'escalade** : un scraper banni revient à l'expiration avec la même durée.
  Pas de réponse HTTP 429 préalable, pas de durée croissante.
- **Pas de disjoncteur** : aucun plafond sur le nombre ou la taille des bans (choix
  assumé : la liste blanche sert de rattrapage). Avec le durcissement par la charge,
  les seuils peuvent descendre jusqu'à `min_threshold` : surveiller les premiers jours.
- Les plages RDAP non résolues (budget épuisé, échec réseau) ne sont jamais
  bannies ; l'échec est journalisé et retenté plus tard.
- `nftables.service` avec `flush ruleset` efface la table `banbot` à chaque
  rechargement (voir les commentaires de `banbot.service.example`).

## Fichiers

| Fichier | Rôle |
|---|---|
| `banbot.py` | le démon et ses commandes |
| `banbot.conf.example` | configuration d'exemple |
| `banbot.service.example` | unité systemd d'exemple |
| `/etc/banbot/banbot.conf` | configuration |
| `/etc/banbot/whitelist.txt` | plages à ne jamais bannir, un CIDR par ligne (créé par `whitelist add`) |
| `/var/lib/banbot/ip_ranges.json` | cache des plages RDAP |
| `/var/lib/banbot/watched.jsonl` | constats « IP surveillée prise dans un ban » (si `watch_*`) |
