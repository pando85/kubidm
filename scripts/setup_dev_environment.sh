#!/bin/bash

# run this, it'll set up a bunch of default stuff
# - reset the admin and idm_admin users
# - set up a test user
# - set up a test group
# - set up a test oauth2 rp (https://kubidm.com)
# - prompt to reset testuser's creds online

set -e

if [ -z "${BUILD_MODE}" ]; then
    BUILD_MODE=""
fi

# if they passed --help then output the help
if [ "${1}" == "--help" ]; then
    echo "Usage: $0 [--remove-db]"
    echo "  --remove-db: remove the existing DB before running"
    echo "  Env vars:"
    echo " BUILD_MODE - default=--debug, set to '--release' to build binaries in release mode"
    exit 0
fi
if [ ! -f Cargo.toml ]; then
    if [ "$(basename "$(pwd)")" == "kubidm" ]; then
        cd server/daemon || exit 1
    else
        echo "Please run from the server/daemon dir, I can't tell where you are..."
        exit 1
    fi
fi


# if --remove-db is in the command line args then remove the DB
if [ -z "${REMOVE_TEST_DB}" ]; then
    if [ "${1}" == "--remove-db" ]; then
        REMOVE_TEST_DB=1
    else
        REMOVE_TEST_DB=0
    fi
fi


# defaults
KUBIDM_CONFIG_FILE="../../scripts/insecure_server.toml"
KUBIDM_URL="$(grep -E 'origin.*https' "${KUBIDM_CONFIG_FILE}" | awk '{print $NF}' | tr -d '"')"
KUBIDM_CA_PATH="/tmp/kubidm/chain.pem"

# wait for them to shut down the server if it's running...
while true; do
    if [ "$(pgrep kubidmd | wc -l)" -eq 1 ]; then
        break
    fi
    echo "Start the kubidmd server first please!"

    while true; do
        echo "Waiting for you to start the server... testing ${KUBIDM_URL}"
        curl --cacert "${KUBIDM_CA_PATH}" -fs "${KUBIDM_URL}" >/dev/null && break
        sleep 2
    done
done

# needed for the CLI tools to do their thing
export KUBIDM_URL
export KUBIDM_CA_PATH
export KUBIDM_CONFIG_FILE

# string things
TEST_USER_NAME="testuser"
TEST_USER_DISPLAY="Test Crab"
TEST_GROUP="test_users"
OAUTH2_RP_ID="test_oauth2"
OAUTH2_RP_DISPLAY="test_oauth2"

# commands to run things
KUBIDM="cargo run ${BUILD_MODE} --manifest-path ../../Cargo.toml --bin kubidm -- "
KUBIDMD="cargo run ${BUILD_MODE} -p daemon --bin kubidmd -- "

if [ "${REMOVE_TEST_DB}" -eq 1 ]; then
    echo "Removing the existing DB!"
    rm /tmp/kubidm/kubidm.db || true
fi

export KUBIDM_CONFIG="../../scripts/insecure_server.toml"
IDM_ADMIN_USER="idm_admin@localhost"

echo "Resetting the idm_admin user..."
IDM_ADMIN_PASS_RAW="$(${KUBIDMD} scripting recover-account idm_admin 2>&1)"
IDM_ADMIN_PASS="$(echo "${IDM_ADMIN_PASS_RAW}" | grep output | jq -r .output)"
if [ -z "${IDM_ADMIN_PASS}" ] || [ "${IDM_ADMIN_PASS}" == "null" ]; then
    echo "Failed to reset idm_admin password!"
    echo "Raw output:"
    echo "${IDM_ADMIN_PASS_RAW}"
    exit 1
fi
echo "idm_admin pass: '${IDM_ADMIN_PASS}'"

echo "login with idm_admin"
${KUBIDM} login -D "${IDM_ADMIN_USER}" --password "${IDM_ADMIN_PASS}"

# create group test_users (ignore error if already exists)
${KUBIDM} group create "${TEST_GROUP}" -D "${IDM_ADMIN_USER}" || echo "Group ${TEST_GROUP} already exists, continuing..."

# create testuser (person) (ignore error if already exists)
${KUBIDM} person create "${TEST_USER_NAME}" "${TEST_USER_DISPLAY}" -D "${IDM_ADMIN_USER}" || echo "Person ${TEST_USER_NAME} already exists, continuing..."

echo "Adding ${TEST_USER_NAME} to ${TEST_GROUP}"
${KUBIDM} group add-members "${TEST_GROUP}" "${TEST_USER_NAME}" -D "${IDM_ADMIN_USER}" || echo "Member already exists, continuing..."

echo "Enable experimental UI for admin idm_admin ${TEST_USER_NAME}"
${KUBIDM} group add-members idm_ui_enable_experimental_features "${IDM_ADMIN_USER}" "${TEST_USER_NAME}" -D "${IDM_ADMIN_USER}" || echo "UI experimental features membership already set, continuing..."

# create oauth2 rp for kubidm.com
echo "Creating the kubidm.com OAuth2 RP"
${KUBIDM} system oauth2 create "kubidm.com" "Kubidm.com" "https://kubidm.com" -D "${IDM_ADMIN_USER}" || echo "OAuth2 RP kubidm.com already exists, continuing..."
echo "Creating the kubidm.com OAuth2 RP Scope Map"
${KUBIDM} system oauth2 update-scope-map "kubidm.com" "${TEST_GROUP}" openid -D "${IDM_ADMIN_USER}" || true
echo "Creating the kubidm.com OAuth2 RP Supplemental Scope Map"
${KUBIDM} system oauth2 update-sup-scope-map "kubidm.com" "${TEST_GROUP}" admin -D "${IDM_ADMIN_USER}" || true


# create oauth2 rp for localhost:10443 - for oauth2 proxy testing
echo "Creating the ${OAUTH2_RP_ID} OAuth2 RP"
${KUBIDM} system oauth2 create "${OAUTH2_RP_ID}" "${OAUTH2_RP_DISPLAY}" "https://localhost:10443" -D "${IDM_ADMIN_USER}" || echo "OAuth2 RP ${OAUTH2_RP_ID} already exists, continuing..."
echo "Creating the ${OAUTH2_RP_ID} OAuth2 RP Scope Map - Group ${TEST_GROUP}"
${KUBIDM} system oauth2 update-scope-map "${OAUTH2_RP_ID}" "${TEST_GROUP}" openid -D "${IDM_ADMIN_USER}" || true
echo "Creating the ${OAUTH2_RP_ID} OAuth2 RP Supplemental Scope Map"
${KUBIDM} system oauth2 update-sup-scope-map "${OAUTH2_RP_ID}" "${TEST_GROUP}" admin -D "${IDM_ADMIN_USER}" || true

echo "Creating a claim map for RS ${OAUTH2_RP_ID}"
${KUBIDM} system oauth2 update-claim-map "${OAUTH2_RP_ID}" testclaim "${TEST_GROUP}" foo bar -D "${IDM_ADMIN_USER}" || true

echo "Creating the OAuth2 RP Secondary Supplemental Crab-baite Scope Map.... wait, no that's not a thing."

echo "Checking the OAuth2 RP Exists"
${KUBIDM} system oauth2 list -D "${IDM_ADMIN_USER}" | grep -A10 "${OAUTH2_RP_ID}"

# config auth2
echo "Pulling secret for the ${OAUTH2_RP_ID} OAuth2 RP"
OAUTH2_SECRET="$(${KUBIDM} system oauth2 show-basic-secret -o json "${OAUTH2_RP_ID}" -D "${IDM_ADMIN_USER}")"
echo "${OAUTH2_SECRET}"

echo "Creating cred reset link for ${TEST_USER_NAME}"
${KUBIDM} person credential create-reset-token "${TEST_USER_NAME}" -D "${IDM_ADMIN_USER}"

echo "Done!"

echo "###################################"
echo "idm_admin password: ${IDM_ADMIN_PASS}"
echo "UI URL:             ${KUBIDM_URL}"
echo "OAuth2 RP ID:       ${OAUTH2_RP_ID}"
echo "OAuth2 Secret:      $(echo "${OAUTH2_SECRET}" | jq  -r .secret)"
echo "###################################"
