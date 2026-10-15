#!/bin/bash
#
# script to check OpenPGP Application features
#

exeName=$0

# Every file of the tests stays next to the script, whatever the current directory
script_path="$(realpath -e -- "${BASH_SOURCE[0]}")" || exit 1
base_dir="$(dirname -- "${script_path}")"
if [[ ! -f "${base_dir}/manual.sh" ]]; then
  echo "Cannot locate the script directory" >&2
  exit 1
fi
gnupg_home_dir="${base_dir}/gnupg"
work_dir="${base_dir}/work"

VERBOSE=false
EXPERT=false

#===============================================================================
#
#     help - Prints script help and usage
#
#===============================================================================
# shellcheck disable=SC2154  # var is referenced but not assigned
help() {
  echo
  echo "Usage: ${exeName} <options>"
  echo
  echo "Options:"
  echo
  echo "  -c <init|reset|reset_all|switch|card|status|encrypt|decrypt|encrypt_decrypt|sign|verify|sign_verify|authenticate|all|default>  : Requested command"
  echo "  -e     : Expert mode"
  echo "  -v     : Verbose mode"
  echo "  -h     : Displays this help"
  echo
  exit 1
}

#===============================================================================
#
#     private_dir - Create a private directory, refusing a symbolic link
#
#===============================================================================
private_dir() {
  if [[ -L "$1" ]]; then
    echo "Refusing the symbolic link '$1'" >&2
    return 1
  fi
  mkdir -p -- "$1" && chmod 700 -- "$1"
}

#===============================================================================
#
#     clean_work - Remove the files of the encrypt, sign and authenticate tests
#
#===============================================================================
clean_work() {
  rm -f -- "${work_dir}"/foo*
}

#===============================================================================
#
#     reset - Kill running process, ensure clear next operation
#
#===============================================================================
reset() {
  # Kill the test homedir agent/scdaemon only, leaving the prod ~/.gnupg
  # agent (and its cached passphrases) untouched.
  gpgconf --homedir "${gnupg_home_dir}" --kill all 2>/dev/null
}

#===============================================================================
#
#     reset_all - Kill every gpg-agent/scdaemon on the machine
#
#===============================================================================
reset_all() {
  # Global kill, including the prod ~/.gnupg agent: useful to free the card
  # reader when a backup/restore leaves a daemon holding the token.
  killall scdaemon gpg-agent 2>/dev/null
}

#===============================================================================
#
#     switch - Use the card of the slot selected on the device
#
#===============================================================================
switch() {
  local card_status=""

  # The slot change is not notified to the PC: restart scdaemon to read the new card
  gpgconf --homedir "${gnupg_home_dir}" --kill scdaemon 2>/dev/null
  gpg-connect-agent --homedir "${gnupg_home_dir}" "scd serialno" "learn --force" /bye >/dev/null
  card_status=$(gpg --homedir "${gnupg_home_dir}" --card-status 2>/dev/null)
  if [[ -z "${card_status}" ]]; then
    echo "No card found"
    return 1
  fi
  grep -E "^(Serial number|Key attributes|General key info)" <<< "${card_status}"
  if grep "General key info" <<< "${card_status}" | grep -q "none"; then
    # No default key from another slot
    rm -f "${gnupg_home_dir}/gpg.conf"
    echo "No key on this slot: generate them with '-c card', then run '-c default'"
  else
    default
  fi
}

#===============================================================================
#
#     default - Set default key in conf file
#
#===============================================================================
default() {
  private_dir "${gnupg_home_dir}" || return 1

  recipient=$(gpg --homedir "${gnupg_home_dir}" --card-status | grep "General key info" | awk  '{print $NF}')

  if [[ -z "${recipient}" ]]; then
    echo "No card found: default key not set"
    return 1
  fi
  if [[ ${recipient} =~ "none" ]]; then
    read -r -p "Enter default key name: " recipient
  fi

  {
    echo "default-key ${recipient}"
    echo "default-recipient ${recipient}"
   } > "${gnupg_home_dir}/gpg.conf"
}

#===============================================================================
#
#     init - Init the gnupg config, start from an empty keyring
#
#===============================================================================
init() {
  reset

  # Cleanup old gnupg home directory
  rm -fr -- "${gnupg_home_dir}"
  clean_work
  private_dir "${gnupg_home_dir}" || return 1

  {
    echo reader-port \"Ledger token\"
    echo allow-admin
    echo enable-pinpad-varlen
    echo card-timeout 1
    echo disable-ccid
    echo pcsc-shared
  } > "${gnupg_home_dir}/scdaemon.conf"

  if [[ ${EXPERT} == true ]]; then
    # The trace holds the APDUs: keep it in the private gnupg home directory
    {
      echo log-file "${gnupg_home_dir}/scd.log"
      echo debug-level guru
      echo debug-all
    } >> "${gnupg_home_dir}/scdaemon.conf"
  fi

  # Enable ssh-agent emulation, needed to exercise the AUT key
  {
    echo enable-ssh-support
  } > "${gnupg_home_dir}/gpg-agent.conf"

  gpgconf --homedir "${gnupg_home_dir}" --reload scdaemon
}

#===============================================================================
#
#     card - Edit the card status and configuration
#
#===============================================================================
card() {
  local expert_mode=""

  [[ ${EXPERT} == true ]] && expert_mode="--expert"

  gpg --homedir "${gnupg_home_dir}" ${expert_mode} --card-edit
  # Set default key name after card edit
  default
}

#===============================================================================
#
#     card - Show the card status and configuration
#
#===============================================================================
status() {
  gpg --homedir "${gnupg_home_dir}" --with-keygrip --card-status
}

#===============================================================================
#
#     encrypt - Encrypt a clear file
#
#===============================================================================
encrypt() {
  local verbose_mode=""

  reset
  private_dir "${work_dir}" || return 1
  clean_work
  echo CLEAR > "${work_dir}/foo.txt"

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --encrypt "${work_dir}/foo.txt"
}

#===============================================================================
#
#     decrypt - Decrypt a file and compare with original clear content
#
#===============================================================================
decrypt() {
  local verbose_mode=""
  local ret

  reset

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  # Check with original clear file
  if gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --decrypt "${work_dir}/foo.txt.gpg" > "${work_dir}/foo_dec.txt" &&
     diff "${work_dir}/foo.txt" "${work_dir}/foo_dec.txt" >/dev/null; then
    echo "Success !"
    ret=0
  else
    echo "Decryption error!"
    ret=1
  fi
  clean_work
  return ${ret}
}

#===============================================================================
#
#     sign - Sign a file
#
#===============================================================================
sign() {
  local verbose_mode=""

  reset
  private_dir "${work_dir}" || return 1
  clean_work
  echo CLEAR > "${work_dir}/foo.txt"

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --sign "${work_dir}/foo.txt"
}

#===============================================================================
#
#     verify - Verify a file signature
#
#===============================================================================
verify() {
  local verbose_mode=""
  local ret

  reset

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  if gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --verify "${work_dir}/foo.txt.gpg"; then
    echo "Success !"
    ret=0
  else
    echo "Signature error!"
    ret=1
  fi
  clean_work
  return ${ret}
}

#===============================================================================
#
#     sign_verify - Sign a file then verify its signature (SIG key roundtrip)
#
#===============================================================================
sign_verify() {
  sign && verify
}

#===============================================================================
#
#     encrypt_decrypt - Encrypt a file then decrypt it back (DEC key roundtrip)
#
#===============================================================================
encrypt_decrypt() {
  encrypt && decrypt
}

#===============================================================================
#
#     all - Run all tests (SIG, DEC, AUT key roundtrip)
#
#===============================================================================
all() {
  sign_verify && encrypt_decrypt && authenticate
}

#===============================================================================
#
#     authenticate - Exercise the AUT key through gpg-agent ssh support
#
#===============================================================================
authenticate() {
  local ret

  reset
  private_dir "${work_dir}" || return 1
  clean_work

  # gpg-agent must expose the card auth key on its ssh socket
  export GNUPGHOME="${gnupg_home_dir}"
  gpg-connect-agent updatestartuptty /bye >/dev/null
  SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
  export SSH_AUTH_SOCK

  # Retrieve the public AUT key advertised by the card
  if ! ssh-add -L > "${work_dir}/foo_auth.pub" 2>/dev/null || [[ ! -s "${work_dir}/foo_auth.pub" ]]; then
    echo "No authentication key exposed by the card!"
    echo "(check the card 'Authentication key' and that the AUT key is generated)"
    clean_work
    return 1
  fi

  [[ ${VERBOSE} == true ]] && cat "${work_dir}/foo_auth.pub"

  # Sign a file with the card AUT key (via the agent), then verify it
  echo CLEAR > "${work_dir}/foo.txt"
  echo "test@ledger.fr $(cat "${work_dir}/foo_auth.pub")" > "${work_dir}/foo_allowed"

  if ssh-keygen -Y sign -f "${work_dir}/foo_auth.pub" -n file "${work_dir}/foo.txt" &&
     ssh-keygen -Y verify -f "${work_dir}/foo_allowed" -I test@ledger.fr -n file \
       -s "${work_dir}/foo.txt.sig" < "${work_dir}/foo.txt"; then
    echo "Success !"
    ret=0
  else
    echo "Authentication error!"
    ret=1
  fi
  clean_work
  return ${ret}
}

#===============================================================================
#
#     Parsing parameters
#
#===============================================================================

if (($# < 1)); then
  help
fi

while getopts ":c:evh" opt; do
  case $opt in

    c)
      case ${OPTARG} in
        init|reset|reset_all|switch|card|status|encrypt|decrypt|encrypt_decrypt|sign|verify|sign_verify|authenticate|all|default)
          CMD=${OPTARG}
          ;;
        *)
          echo "Wrong parameter '${OPTARG}'!"
          exit 1
          ;;
      esac
      ;;

    e)  EXPERT=true ;;
    v)  VERBOSE=true ;;
    h)  help ;;

    \?) echo "Unknown option: -${OPTARG}" >&2; exit 1;;
    : ) echo "Missing option argument for -${OPTARG}" >&2; exit 1;;
    * ) echo "Unimplemented option: -${OPTARG}" >&2; exit 1;;
  esac
done

#===============================================================================
#
#     Main
#
#===============================================================================

# execute the command
${CMD}
