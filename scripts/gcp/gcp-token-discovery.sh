#!/usr/bin/env bash
#
# gcp-token-discovery.sh
#
# Discover information available from a Google OAuth access token (AT)
# or refresh token (RT), while showing the API endpoint used for each query.
#
# Requirements:
#   curl
#   jq
#
# Usage:
#   ./gcp-token-discovery.sh '<TOKEN>'
#
# Refresh token:
#   GOOGLE_CLIENT_ID='....apps.googleusercontent.com' \
#   GOOGLE_CLIENT_SECRET='....' \
#     ./gcp-token-discovery.sh '1//....'
#
# Options:
#   -t, --token TOKEN
#   -i, --client-id CLIENT_ID
#   -s, --client-secret CLIENT_SECRET
#

set -u

TOKEN=""
CLIENT_ID="${GOOGLE_CLIENT_ID:-}"
CLIENT_SECRET="${GOOGLE_CLIENT_SECRET:-}"

TOKENINFO="https://oauth2.googleapis.com/tokeninfo"
TOKEN_ENDPOINT="https://oauth2.googleapis.com/token"
USERINFO="https://openidconnect.googleapis.com/v1/userinfo"
CRM="https://cloudresourcemanager.googleapis.com/v3"

usage() {
    cat <<EOF
Usage:
  $0 TOKEN
  $0 --token TOKEN [--client-id ID] [--client-secret SECRET]

Examples:

  # Access token
  $0 'ya29....'

  # Refresh token
  $0 '1//....' \
      --client-id '123.apps.googleusercontent.com' \
      --client-secret 'GOCSPX-....'

Environment variables:
  GOOGLE_CLIENT_ID
  GOOGLE_CLIENT_SECRET
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--token)
            TOKEN="$2"
            shift 2
            ;;
        -i|--client-id)
            CLIENT_ID="$2"
            shift 2
            ;;
        -s|--client-secret)
            CLIENT_SECRET="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ -z "$TOKEN" ]]; then
                TOKEN="$1"
                shift
            else
                echo "Unknown argument: $1" >&2
                exit 1
            fi
            ;;
    esac
done

[[ -n "$TOKEN" ]] || {
    usage
    exit 1
}

command -v curl >/dev/null || {
    echo "ERROR: curl required" >&2
    exit 1
}

command -v jq >/dev/null || {
    echo "ERROR: jq required" >&2
    exit 1
}


#
# Formatting
#

section() {
    printf '\n============================================================\n'
    printf '%s\n' "$1"
    printf '============================================================\n'
}

subsection() {
    printf '\n--- %s ---\n' "$1"
}

api() {
    printf 'API: %s\n\n' "$1"
}


#
# Perform authenticated GET.
#

api_get() {
    local url="$1"
    local name="$2"
    local tmp
    local code

    tmp="$(mktemp)"

    code="$(
        curl -sS \
            -o "$tmp" \
            -w '%{http_code}' \
            -H "Authorization: Bearer $AT" \
            "$url"
    )"

    printf '[%s] HTTP %s\n' "$name" "$code"

    if [[ -s "$tmp" ]]; then
        jq . "$tmp" 2>/dev/null || cat "$tmp"
    fi

    rm -f "$tmp"

    [[ "$code" =~ ^2 ]]
}


#
# TOKEN TYPE DETECTION
#

section "TOKEN TYPE DETECTION"

api "GET oauth2.googleapis.com/tokeninfo?access_token=<TOKEN>"

TOKENINFO_RESPONSE="$(
    curl -sS \
        "${TOKENINFO}?access_token=${TOKEN}" \
        2>/dev/null || true
)"

if jq -e '
    (.scope != null) or
    (.expires_in != null) or
    (.exp != null) or
    (.email != null) or
    (.sub != null)
' >/dev/null 2>&1 <<<"$TOKENINFO_RESPONSE"; then

    TYPE="access_token"
    AT="$TOKEN"

    echo "Detected: Google OAuth ACCESS TOKEN"

else

    TYPE="possible_refresh_token"

    echo "Token was not recognized by tokeninfo as an access token."
    echo "Treating as possible REFRESH TOKEN."

    if [[ -z "$CLIENT_ID" ]]; then
        cat <<EOF

Cannot test/exchange the possible refresh token without its OAuth client.

Required:
  --client-id CLIENT_ID

And, for clients requiring it:
  --client-secret CLIENT_SECRET

Example:

  $0 --token '<RT>' \\
     --client-id '123.apps.googleusercontent.com' \\
     --client-secret 'GOCSPX-...'

EOF
        exit 2
    fi

    section "REFRESH TOKEN EXCHANGE"

    api "POST oauth2.googleapis.com/token  {grant_type=refresh_token, refresh_token=<RT>, client_id=<CLIENT_ID>, client_secret=<optional>}"

    CURL_ARGS=(
        -sS
        -X POST
        "$TOKEN_ENDPOINT"
        -d "grant_type=refresh_token"
        --data-urlencode "refresh_token=$TOKEN"
        --data-urlencode "client_id=$CLIENT_ID"
    )

    if [[ -n "$CLIENT_SECRET" ]]; then
        CURL_ARGS+=(
            --data-urlencode "client_secret=$CLIENT_SECRET"
        )
    fi

    REFRESH_RESPONSE="$(curl "${CURL_ARGS[@]}")"

    echo "$REFRESH_RESPONSE" | jq .

    AT="$(jq -r '.access_token // empty' <<<"$REFRESH_RESPONSE")"

    if [[ -z "$AT" ]]; then
        echo
        echo "ERROR: refresh-token exchange did not return an access token."
        exit 3
    fi

    TYPE="refresh_token"

    echo
    echo "Refresh exchange successful."
    echo "Continuing discovery with returned access token."
fi


#
# ACCESS TOKEN METADATA
#

section "ACCESS TOKEN METADATA"

api "GET oauth2.googleapis.com/tokeninfo?access_token=<AT>"

TOKENINFO_RESPONSE="$(
    curl -sS \
        "${TOKENINFO}?access_token=${AT}"
)"

echo "$TOKENINFO_RESPONSE" | jq .

SCOPES="$(
    jq -r '.scope // ""' <<<"$TOKENINFO_RESPONSE"
)"

EMAIL="$(
    jq -r '.email // ""' <<<"$TOKENINFO_RESPONSE"
)"

SUB="$(
    jq -r '.sub // ""' <<<"$TOKENINFO_RESPONSE"
)"

AUD="$(
    jq -r '.aud // ""' <<<"$TOKENINFO_RESPONSE"
)"

AZP="$(
    jq -r '.azp // ""' <<<"$TOKENINFO_RESPONSE"
)"

EXP="$(
    jq -r '.exp // ""' <<<"$TOKENINFO_RESPONSE"
)"


#
# TOKEN SUMMARY
#

section "TOKEN SUMMARY"

api "Derived locally from tokeninfo response"

printf '%-20s %s\n' "Input type:" "$TYPE"
printf '%-20s %s\n' "Subject:" "${SUB:-unknown}"
printf '%-20s %s\n' "Email:" "${EMAIL:-unknown}"
printf '%-20s %s\n' "Audience:" "${AUD:-unknown}"
printf '%-20s %s\n' "Authorized party:" "${AZP:-unknown}"
printf '%-20s %s\n' "Expiration:" "${EXP:-unknown}"

echo
echo "Scopes:"

if [[ -n "$SCOPES" ]]; then
    tr ' ' '\n' <<<"$SCOPES" | sed 's/^/  /'
else
    echo "  unknown"
fi


#
# OIDC USERINFO
#

section "OIDC USERINFO"

api "GET openidconnect.googleapis.com/v1/userinfo  [Authorization: Bearer <AT>]"

api_get "$USERINFO" "userinfo" || true


#
# ORGANIZATION DISCOVERY
#

section "GCP ORGANIZATION DISCOVERY"

api "GET cloudresourcemanager.googleapis.com/v3/organizations:search  [Authorization: Bearer <AT>]"

ORG_TMP="$(mktemp)"

ORG_CODE="$(
    curl -sS \
        -o "$ORG_TMP" \
        -w '%{http_code}' \
        -H "Authorization: Bearer $AT" \
        "${CRM}/organizations:search"
)"

echo "HTTP $ORG_CODE"

jq . "$ORG_TMP" 2>/dev/null || cat "$ORG_TMP"

ORG_IDS="$(
    jq -r '
        .organizations[]?.name
        | select(startswith("organizations/"))
    ' "$ORG_TMP" 2>/dev/null
)"

rm -f "$ORG_TMP"


#
# ORGANIZATION DETAILS
#

if [[ -n "$ORG_IDS" ]]; then

    section "ORGANIZATION DETAILS"

    while IFS= read -r org; do

        [[ -n "$org" ]] || continue

        subsection "$org"

        api "GET cloudresourcemanager.googleapis.com/v3/${org}"

        api_get "${CRM}/${org}" "$org" || true

    done <<<"$ORG_IDS"

else

    echo
    echo "No organizations returned."
    echo
    echo "IMPORTANT:"
    echo "This does NOT prove that the principal has no GCP organization."
    echo "Organization discovery is constrained by OAuth scope and IAM."

fi


#
# PROJECT DISCOVERY
#

section "GCP PROJECT DISCOVERY"

api "GET cloudresourcemanager.googleapis.com/v3/projects:search  [Authorization: Bearer <AT>]"

PROJECT_TMP="$(mktemp)"

PROJECT_CODE="$(
    curl -sS \
        -o "$PROJECT_TMP" \
        -w '%{http_code}' \
        -H "Authorization: Bearer $AT" \
        "${CRM}/projects:search"
)"

echo "HTTP $PROJECT_CODE"

jq . "$PROJECT_TMP" 2>/dev/null || cat "$PROJECT_TMP"


#
# Extract discovered projects.
#

PROJECT_NAMES="$(
    jq -r '
        .projects[]?.name
        | select(startswith("projects/"))
    ' "$PROJECT_TMP" 2>/dev/null
)"


#
# PROJECT SUMMARY
#

section "PROJECT SUMMARY"

api "Derived locally from GET cloudresourcemanager.googleapis.com/v3/projects:search"

jq -r '
    .projects[]? |
    [
      (.projectId // ""),
      (.name // ""),
      (.displayName // ""),
      (.parent // ""),
      (.state // "")
    ] |
    @tsv
' "$PROJECT_TMP" 2>/dev/null |
awk -F'\t' '
BEGIN {
    printf "%-30s %-24s %-30s %-30s %s\n",
           "PROJECT_ID","RESOURCE","DISPLAY_NAME","PARENT","STATE"
}
{
    printf "%-30s %-24s %-30s %-30s %s\n",
           $1,$2,$3,$4,$5
}'


#
# PROJECT DETAILS
#

if [[ -n "$PROJECT_NAMES" ]]; then

    section "PROJECT DETAILS"

    while IFS= read -r project; do

        [[ -n "$project" ]] || continue

        subsection "$project"

        api "GET cloudresourcemanager.googleapis.com/v3/${project}"

        api_get "${CRM}/${project}" "$project" || true

    done <<<"$PROJECT_NAMES"

else

    echo "No projects returned."
fi


#
# RESOURCE HIERARCHY
#

section "RESOURCE HIERARCHY"

api "Parents derived from projects:search; then GET /v3/{folders|organizations}/<ID>"

PARENTS="$(
    jq -r '
        .projects[]?.parent // empty
    ' "$PROJECT_TMP" |
    sort -u
)"

rm -f "$PROJECT_TMP"

if [[ -z "$PARENTS" ]]; then

    echo "No parent resources exposed by project search."

else

    while IFS= read -r parent; do

        [[ -n "$parent" ]] || continue

        echo
        echo "Parent: $parent"

        case "$parent" in

            organizations/*)

                api "GET cloudresourcemanager.googleapis.com/v3/${parent}"

                api_get "${CRM}/${parent}" "$parent" || true
                ;;

            folders/*)

                api "GET cloudresourcemanager.googleapis.com/v3/${parent}"

                api_get "${CRM}/${parent}" "$parent" || true
                ;;

            *)

                echo "Unknown parent resource type: $parent"
                ;;

        esac

    done <<<"$PARENTS"

fi


#
# GCLOUD EQUIVALENTS
#

section "GCLOUD EQUIVALENTS"

api "No additional API calls; equivalent Cloud SDK commands"

if command -v gcloud >/dev/null 2>&1; then

    echo "gcloud installed:"
    gcloud version 2>/dev/null | head -5

    echo
    echo "Equivalent arbitrary-AT usage:"
    echo
    echo "  printf '%s' \"\$AT\" > /tmp/gcp-at"
    echo "  chmod 600 /tmp/gcp-at"
    echo
    echo "  gcloud organizations list --access-token-file=/tmp/gcp-at"
    echo "  gcloud projects list      --access-token-file=/tmp/gcp-at"

else

    echo "gcloud not installed; REST discovery completed without it."

fi


#
# INTERPRETATION
#

section "INTERPRETATION"

cat <<'EOF'
Discovery results are authorization-context dependent.

A positive result establishes that the resource was visible to this
token/principal.

A negative result generally does NOT establish that the resource does
not exist or that the identity has no relationship to it.

For most GCP APIs:

    OAuth scope permits API operation
                 AND
       IAM permits resource access
                  |
                  v
            resource visible
EOF
