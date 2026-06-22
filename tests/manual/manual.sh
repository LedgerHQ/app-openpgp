#!/bin/bash
#
# script to check OpenPGP Application features
#

exeName=$(readlink "$0")
[[ -z ${exeName} ]] && exeName=$0
dirName=$(dirname "${exeName}")

gnupg_home_dir="$(realpath "${dirName}/gnupg")"

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
  echo "  -c <init|reset|reset_all|card|status|encrypt|decrypt|encrypt_decrypt|sign|verify|sign_verify|authenticate|default>  : Requested command"
  echo "  -e     : Expert mode"
  echo "  -v     : Verbose mode"
  echo "  -h     : Displays this help"
  echo
  exit 1
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
#     default - Set default key in conf file
#
#===============================================================================
default() {
  dir=$(basename "${gnupg_home_dir}")
  if [[ ! -d "${dir}" ]]; then
    mkdir "${dir}"
    chmod 700 "${dir}"
  fi

  recipient=$(gpg --homedir "${gnupg_home_dir}" --card-status | grep "General key info" | awk  '{print $NF}')

  if [[ ${recipient} =~ "none" ]]; then
    read -r -p "Enter default key name: " recipient
  fi

  {
    echo "default-key ${recipient}"
    echo "default-recipient ${recipient}"
   } > "${dir}/gpg.conf"
}

#===============================================================================
#
#     init - Init the gnupg config, start from an empty keyring
#
#===============================================================================
init() {
  reset

  # Cleanup old gnupg home directory
  dir=$(basename "${gnupg_home_dir}")
  rm -fr "${dir}" foo.txt*
  mkdir "${dir}"
  chmod 700 "${dir}"

  {
    echo reader-port \"Ledger token\"
    echo allow-admin
    echo enable-pinpad-varlen
    echo card-timeout 1
    echo disable-ccid
    echo pcsc-shared
  } > "${dir}/scdaemon.conf"

  if [[ ${EXPERT} == true ]]; then
    {
      echo log-file /tmp/scd.log
      echo debug-level guru
      echo debug-all
    } >> "${dir}/scdaemon.conf"
  fi

  # Enable ssh-agent emulation, needed to exercise the AUT key
  {
    echo enable-ssh-support
  } > "${dir}/gpg-agent.conf"

  gpgconf --reload scdaemon
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
  rm -fr foo*
  echo CLEAR > foo.txt

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --encrypt foo.txt
}

#===============================================================================
#
#     decrypt - Decrypt a file and compare with original clear content
#
#===============================================================================
decrypt() {
  local verbose_mode=""

  reset

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --decrypt foo.txt.gpg > foo_dec.txt

  # Check with original clear file
  if diff foo.txt foo_dec.txt >/dev/null; then
    echo "Success !"
  else
    echo "Decryption error!"
  fi
  rm -fr foo*
}

#===============================================================================
#
#     sign - Sign a file
#
#===============================================================================
sign() {
  local verbose_mode=""

  reset
  rm -fr foo*
  echo CLEAR > foo.txt

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --sign foo.txt
}

#===============================================================================
#
#     verify - Verify a file signature
#
#===============================================================================
verify() {
  local verbose_mode=""

  reset

  [[ ${VERBOSE} == true ]] && verbose_mode="--verbose"

  gpg --homedir "${gnupg_home_dir}" ${verbose_mode} --verify foo.txt.gpg
  rm -fr foo*
}

#===============================================================================
#
#     sign_verify - Sign a file then verify its signature (SIG key roundtrip)
#
#===============================================================================
sign_verify() {
  sign
  verify
}

#===============================================================================
#
#     encrypt_decrypt - Encrypt a file then decrypt it back (DEC key roundtrip)
#
#===============================================================================
encrypt_decrypt() {
  encrypt
  decrypt
}

#===============================================================================
#
#     authenticate - Exercise the AUT key through gpg-agent ssh support
#
#===============================================================================
authenticate() {
  reset
  rm -fr foo*

  # gpg-agent must expose the card auth key on its ssh socket
  export GNUPGHOME="${gnupg_home_dir}"
  gpg-connect-agent updatestartuptty /bye >/dev/null
  SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
  export SSH_AUTH_SOCK

  # Retrieve the public AUT key advertised by the card
  if ! ssh-add -L > foo_auth.pub 2>/dev/null || [[ ! -s foo_auth.pub ]]; then
    echo "No authentication key exposed by the card!"
    echo "(check the card 'Authentication key' and that the AUT key is generated)"
    rm -fr foo*
    return 1
  fi

  [[ ${VERBOSE} == true ]] && cat foo_auth.pub

  # Sign a file with the card AUT key (via the agent), then verify it
  echo CLEAR > foo.txt
  echo "test@ledger.fr $(cat foo_auth.pub)" > foo_allowed

  ssh-keygen -Y sign -f foo_auth.pub -n file foo.txt

  if ssh-keygen -Y verify -f foo_allowed -I test@ledger.fr -n file -s foo.txt.sig < foo.txt; then
    echo "Success !"
  else
    echo "Authentication error!"
  fi
  rm -fr foo*
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
        init|reset|reset_all|card|status|encrypt|decrypt|encrypt_decrypt|sign|verify|sign_verify|authenticate|default)
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
