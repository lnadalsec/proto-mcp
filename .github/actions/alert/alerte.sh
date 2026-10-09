#!/usr/bin/env bash
# Ouvre, commente ou ferme l'issue « [alerte:<clé>] <titre> » (étiquette « alerte »), via gh et GH_TOKEN.
# Entrées : ALERTE_CLE, ALERTE_STATUT (failure|success), ALERTE_TITRE, ALERTE_FICHIER, ALERTE_WEBHOOK,
#           ALERTE_RAPPEL_HEURES, GH_REPO. ALERTE_SIMULATION=1 : aucune écriture (GitHub, webhook), affichage seul.
set -euo pipefail

cle="${ALERTE_CLE:-}"
statut="${ALERTE_STATUT:-}"
titre="${ALERTE_TITRE:-}"
fichier="${ALERTE_FICHIER:-}"
webhook="${ALERTE_WEBHOOK:-}"
rappel_heures="${ALERTE_RAPPEL_HEURES:-0}"
simulation="${ALERTE_SIMULATION:-0}"
depot="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
serveur="${GITHUB_SERVER_URL:-https://github.com}"
etiquette="alerte"
prefixe="[alerte:${cle}]"
lien_run="${serveur}/${depot}/actions/runs/${GITHUB_RUN_ID:-0}"
maintenant="$(date -u '+%Y-%m-%d %H:%M UTC')"

if [ -n "$webhook" ]; then echo "::add-mask::${webhook}"; fi

erreur() {
  echo "::error title=Alerte::$*"
  exit 1
}

[[ "$cle" =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || erreur "clé invalide « ${cle} » (minuscules, chiffres, point, tiret, souligné)"
[[ "$statut" == "failure" || "$statut" == "success" ]] || erreur "statut invalide « ${statut} » (failure ou success)"
[[ -n "$titre" ]] || erreur "titre vide"
[[ "$rappel_heures" =~ ^[0-9]+$ ]] || erreur "rappel-heures doit être un nombre entier"
[[ -n "$depot" ]] || erreur "dépôt inconnu (GH_REPO)"

sortie() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1=$2" >> "$GITHUB_OUTPUT"; fi
}

# Écriture sur GitHub, ou simple affichage en simulation.
ecrire() {
  if [ "$simulation" = "1" ]; then
    printf '[simulation] gh'
    printf ' %q' "$@"
    printf '\n'
  else
    gh "$@"
  fi
}

empreinte_de() {
  if command -v sha256sum > /dev/null; then sha256sum; else shasum -a 256; fi | cut -c1-16
}

# Message court, compatible webhooks entrants Slack (et connecteurs Teams historiques) ou Teams Workflows.
notifie=0
notifier() {
  local message="$1" hote charge
  notifie=1
  [ -n "$webhook" ] || return 0
  hote="$(printf '%s' "$webhook" | sed -E 's#^[A-Za-z]+://([^/:?]+).*#\1#' | tr '[:upper:]' '[:lower:]')"
  case "$hote" in
    *.logic.azure.com | *.powerplatform.com | *.powerautomate.com)
      charge="$(jq -cn --arg t "$message" '{type: "message", attachments: [{contentType: "application/vnd.microsoft.card.adaptive", content: {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", type: "AdaptiveCard", version: "1.4", body: [{type: "TextBlock", text: $t, wrap: true}]}}]}')"
      ;;
    *)
      charge="$(jq -cn --arg t "$message" '{text: $t}')"
      ;;
  esac
  if [ "$simulation" = "1" ]; then
    echo "[simulation] webhook (URL masquée) : ${charge}"
    return 0
  fi
  # L'URL passe par la configuration lue sur l'entrée standard : absente de la ligne de commande et des journaux.
  if ! printf 'url = "%s"\n' "$webhook" | curl --config - --silent --fail --max-time 15 --retry 2 \
    --output /dev/null --header 'Content-Type: application/json' --data-binary "$charge" 2> /dev/null; then
    echo "::warning title=Alerte::notification webhook en échec (URL masquée)"
  fi
}

# Le webhook est le canal principal (docs/monitoring.md, section 3) : si l'écriture sur GitHub échoue
# (API indisponible, droits), un échec est quand même notifié, avec le lien du run à la place de l'issue.
fin() {
  local code=$?
  if [ "$code" -ne 0 ] && [ "$statut" = "failure" ] && [ "$notifie" = "0" ]; then
    notifier "Alerte (${cle}) : ${titre} · ${lien_run} (issue GitHub non écrite : voir le run)"
  fi
  rm -rf "$travail"
}
travail="$(mktemp -d)"
trap fin EXIT

# Corps : rapport (tronqué si besoin) puis pied de page avec l'empreinte des constats.
rapport="${travail}/rapport.md"
empreinte=""
if [ -n "$fichier" ] && [ -s "$fichier" ]; then
  if [ "$(wc -c < "$fichier")" -gt 60000 ]; then
    head -c 60000 "$fichier" > "$rapport"
    printf '\n\n_Rapport tronqué : version complète dans le résumé du run._\n' >> "$rapport"
  else
    cp "$fichier" "$rapport"
  fi
  signatures="$({ grep -o 'alerte:signature=[0-9a-f]*' "$fichier" || true; } | sort -u | tr '\n' ' ')"
  if [ -n "$signatures" ]; then empreinte="$(printf '%s' "$signatures" | empreinte_de)"; fi
else
  printf '_Aucun rapport fourni : voir le run._\n' > "$rapport"
fi
corps="${travail}/corps.md"
{
  cat "$rapport"
  # shellcheck disable=SC2016 # accents graves Markdown, littéraux voulus
  printf '\n---\n\nAlerte `%s` · %s · [run](%s) · issue gérée automatiquement, fermée au rétablissement.\n' "$cle" "$maintenant" "$lien_run"
  if [ -n "$empreinte" ]; then printf '<!-- alerte:empreinte=%s -->\n' "$empreinte"; fi
} > "$corps"

ouvertes="$(gh issue list --repo "$depot" --state open --label "$etiquette" --limit 100 --json number,title \
  | jq -c --arg p "$prefixe" '[.[] | select(.title | startswith($p))] | sort_by(.number)')"
nombre="$(jq 'length' <<< "$ouvertes")"

if [ "$statut" = "success" ]; then
  if [ "$nombre" -eq 0 ]; then
    echo "Aucune alerte ouverte pour ${cle}."
    sortie issue ""
    sortie action aucune
    exit 0
  fi
  for numero in $(jq -r '.[].number' <<< "$ouvertes"); do
    ecrire issue close "$numero" --repo "$depot" --reason completed \
      --comment "Rétabli le ${maintenant} : contrôles de nouveau au vert ([run](${lien_run}))."
    echo "Alerte fermée : ${serveur}/${depot}/issues/${numero}"
    sortie issue "$numero"
  done
  sortie action fermee
  notifier "Rétabli (${cle}) : ${titre} · ${lien_run}"
  exit 0
fi

if [ "$nombre" -eq 0 ]; then
  if ! gh label list --repo "$depot" --search "$etiquette" --json name --jq '.[].name' | grep -qx "$etiquette"; then
    ecrire label create "$etiquette" --repo "$depot" --color B60205 \
      --description "Alerte automatique : surveillance, audit, sécurité, déploiement" || true
  fi
  if [ "$simulation" = "1" ]; then
    ecrire issue create --repo "$depot" --title "${prefixe} ${titre}" --label "$etiquette" --body-file "$corps"
    url="${serveur}/${depot}/issues/0"
  else
    url="$(gh issue create --repo "$depot" --title "${prefixe} ${titre}" --label "$etiquette" --body-file "$corps")"
  fi
  echo "Alerte ouverte : ${url}"
  sortie issue "${url##*/}"
  sortie action creee
  notifier "Alerte (${cle}) : ${titre} · ${url}"
  exit 0
fi

numero="$(jq -r '.[-1].number' <<< "$ouvertes")"
url="${serveur}/${depot}/issues/${numero}"
sortie issue "$numero"
# Option rappel-heures : constat inchangé (même empreinte) signalé il y a moins de N heures → pas de commentaire.
if [ "$rappel_heures" -gt 0 ] && [ -n "$empreinte" ]; then
  precedent="$(gh api --paginate "repos/${depot}/issues/${numero}/comments?per_page=100" \
    --jq '.[] | select(.body | contains("alerte:empreinte=")) | {date: .created_at, body: .body} | @json' | tail -n 1)"
  if [ -z "$precedent" ]; then
    precedent="$(gh issue view "$numero" --repo "$depot" --json body,createdAt --jq '{date: .createdAt, body: .body} | @json')"
  fi
  ancienne="$(jq -r '.body | capture("alerte:empreinte=(?<e>[0-9a-f]+)").e // ""' <<< "$precedent" 2> /dev/null || true)"
  age_heures="$(jq -r '(now - (.date | fromdateiso8601)) / 3600 | floor' <<< "$precedent" 2> /dev/null || echo 999999)"
  if [ "$empreinte" = "$ancienne" ] && [ "$age_heures" -lt "$rappel_heures" ]; then
    echo "Constat inchangé, signalé il y a ${age_heures} h sur ${url} : pas de nouveau commentaire (rappel toutes les ${rappel_heures} h)."
    sortie action inchangee
    exit 0
  fi
fi
ecrire issue comment "$numero" --repo "$depot" --body-file "$corps"
echo "Alerte commentée : ${url}"
sortie action commentee
notifier "Alerte toujours active (${cle}) : ${titre} · ${url}"
