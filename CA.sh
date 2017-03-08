#!/bin/bash
#
# Xiami's CA utility
#
# Author: Xiami <i@f2light.com>
#
# NOTICE
# Using me requires no change to paths in ca.cnf

prog=`realpath $BASH_SOURCE`
wd=`dirname $prog`

_usage="Xiami's CA utility

Usage: $0 [options] command args

Available commands: init, newca, newcert
"
_help="Options:
    --ca=PATH       Path to ca config. Default to ./ca.cnf
    --req=PATH      Path to req config. Default to $wd/conf/req.cnf
    --ext=PATH      Path to extension config. Default to ./x509v3.cnf
    -1
    --noext         Do not use extension. Issue V1 cert.
    --caarg=ARGS    Extra arguments for \`openssl ca\`
    --san=SAN       Provide subjectAltName for newcert. Can appear multiple times

    If your command requires a private key, either -g or -k must exist.
    -g
    --genkey=FORMAT Generate key using specified parameters
                    rsa:<bits> ec:<curve> param:<file>
    -k
    --key=PATH      Use this key

    -h              Show help

Commands:
    chkexp          Print expired certificates
    gencrl          Generate CRL using CA keys
    genocspcert     Generate OCSP Responder certificate (Valid for 90 days)
        args: subject
    init            Init a root CA. Not honor -1 (Valid for 20 years)
        args: subject
    newca           Create an intermediate CA
        args: subject, extension, newcadir
    newcert         Create an end entity certificate
        args: subject, extension
    revoke          Revoke a certificate
        args: filename

Low-level commands:
    newreq          Create a certificate signing request
        args: subject
    showpkey        Show what -g/-k gots
    signreq         Sign a request
        args: request_file, extension

Args:
    subject         Certificate subject. It's a DN
    extension       Cert V3 or CRL V2 extension name
"

# Usage: genpkey <format>
genpkey() {
    local OLD_IFS="$IFS" args
    local -A pkeyopts
    # openssl 1.0.2k genpkey has bugs with DSA key generation
    # DSA private key can be only generated with -paramfile
    #pkeyopts[dsa]=dsa_paramgen_bits
    pkeyopts[ec]=ec_paramgen_curve
    pkeyopts[rsa]=rsa_keygen_bits

    IFS=:
    args=($@)
    IFS="$OLD_IFS"

    if [ "${args[0]}" = param ]; then
        openssl genpkey -paramfile "${args[1]}"
    elif [ -n "${pkeyopts[${args[0]}]}" ]; then
        openssl genpkey -algorithm "${args[0]}" -pkeyopt "${pkeyopts[${args[0]}]}:${args[1]}"
    else
        echo "${args[0]} not supported." >&2
    fi
}

# Usage: mkcadir <dir>
mkcadir() {
    mkdir db
    touch db/index.txt
    echo "01" > db/serial
    echo "01" > db/crlnumber
    mkdir cert
    mkdir privkey
    chmod 700 privkey
    grep -vEe '^(# |#?$)' "$wd/conf/ca.cnf" > ca.cnf

    grep -vEe '^(# |#?$)' "$wd/conf/x509v3.cnf" > x509v3.cnf
    grep -vEe '^(# |#?$)' "$wd/conf/ext.oid" > ext.oid
}

# Usage: mkreq <subj>
mkreq() {
    if [ -z "$PKEY_BLOB" ]; then
        echo "No private key to generate cert req." >&2
        return 1
    fi
    # Process --san
    reqcnfdat=$(<"$CONFIG_REQ")
    if [ -n "$REQ_SAN" ]; then
        reqcnfdat="$reqcnfdat
[ xiami_ca_sh_req_v3ext ]
$REQ_SAN
"
        local reqargs="-reqexts xiami_ca_sh_req_v3ext"
    fi
    openssl req -new -key <(echo "$PKEY_BLOB") -config <(echo "$reqcnfdat") -subj "$1" $reqargs
    if [ $? -ne 0 ]; then
        echo "Failed to get certificate signing request." >&2
        return 1
    fi
}

# Usage: signreq <req_file> <extension>
signreq() {
    local caargs="-config \"$CONFIG_CA\" -notext -in \"$1\""
    if [ -z "$ONLY_V1" ]; then
        caargs="$caargs -extfile \"$CONFIG_EXT\" -extensions \"$2\""
    fi
    caargs="$caargs -batch $CA_ARGS"
    cp -f db/serial last_srl
    eval openssl ca $caargs
    if [ $? -ne 0 ]; then
        echo "Failed to sign certificate." >&2
        return 1
    fi
}

# Low-level commands
cmd_newreq() {
    if [ $# -ne 1 ]; then
        echo "Exact 1 argument required." >&2
        return 1
    fi
    mkreq "$1" || return $?
    echo "$PKEY_BLOB"
}

cmd_showpkey() {
    if [ $# -ne 0 ]; then
        echo "Arguments forbidden." >&2
        return 1
    fi
    if [ -z "$PKEY_BLOB" ]; then
        echo "No key found. Confirm -g/-k provided?" >&2
        return 1
    fi
    openssl pkey -in <(echo "$PKEY_BLOB") -text
}

cmd_signreq() {
    if [ $# -ne 2 ]; then
        echo "Exact 2 arguments required." >&2
        return 1
    fi
    signreq "$@"
    return $?
}

# Commands
cmd_chkexp() {
    local i
    for i in `ls cert`; do
        openssl x509 -in cert/$i -noout -checkend 0 || echo "$i"
    done
}

cmd_gencrl() {
    if [ $# -ne 0 ]; then
        echo "Arguments forbidden." >&2
        return 1
    fi
    # -updatedb can handle UTCTIME only and only converts V to E (1.0.2k)
    eval openssl ca -config \"$CONFIG_CA\" -updatedb $CA_ARGS || return $?
    eval openssl ca -config \"$CONFIG_CA\" -gencrl -out ca.crl $CA_ARGS || return $?
}

cmd_genocspcert() {
    if [ $# -ne 1 ]; then
        echo "Exact 1 argument required." >&2
        return 1
    fi
    local oldocsp crlres
    # Check if current OCSP cert is valid
    oldocsp=`readlink ocsp.crt`
    if [ -n "$oldocsp" ]; then
        oldocsp=${oldocsp#cert/}
        oldocsp=${oldocsp%.pem}
        crlres=`eval openssl ca -config \"$CONFIG_CA\" -status $oldocsp 2>&1 | tail -1`
        if [ "${crlres}" = "$oldocsp=Valid (V)" ] &&
            openssl x509 -in ocsp.crt -noout -checkend 0; then
            echo "Current OCSP cert is still valid!" >&2;
            return 1;
        fi
    fi
    cmd_newcert "$1" ocsp_v3ext || return $?
    ln -sf "cert/$(<last_srl).pem" ocsp.crt
    ln -sf "privkey/$(<last_srl).key" ocsp.key
}

cmd_init() {
    if [ $# -ne 1 ]; then
        echo "Exact 1 argument required." >&2
        return 1
    fi
    if [ -n "`ls -A`" ]; then
        echo "$PWD not empty. Aborting." >&2
        return 1
    fi
    # Generate csr
    local reqdat
    reqdat=`mkreq "$1"` || return $?

    mkcadir

    # Selfsign
    eval openssl ca -config \"$wd/conf/ca.cnf\" -notext -in <(echo "$reqdat") \
        -extfile \"$wd/conf/x509v3.cnf\" \
        -extensions ca_root_v3ext -batch -selfsign -days 7305 \
        -keyfile <(echo "$PKEY_BLOB") $CA_ARGS >/dev/null
    if [ $? -ne 0 ]; then
        echo "Failed to sign certificate." >&2
        return 1
    fi
    echo "$1"

    # Save private key
    echo "$PKEY_BLOB" > privkey/01.key

    return $?
}

cmd_newca() {
    if [ $# -ne 3 ]; then
        echo "Exact 3 arguments required." >&2
        return 1
    fi
    if [ -n "`ls -A "$3" 2>/dev/null`" ]; then
        echo "$3 not empty. Aborting." >&2
        return 1
    fi

    cmd_newcert "$1" "$2" || return $?

    [ ! -d "$3" ] && mkdir -vp "$3"
    if ! pushd "$3" >/dev/null; then
        echo "Failed to enter new ca dir." >&2
        return 1
    fi
    mkcadir
    grep -vEe '^(# |#?$)' "$wd/conf/req.cnf" > req.cnf
    echo "02" > db/serial
    echo "$certdat" > cert/01.pem
    echo "$PKEY_BLOB" > privkey/01.key
    popd >/dev/null
}

cmd_newcert() {
    if [ $# -ne 2 ]; then
        echo "Exact 2 arguments required." >&2
        return 1
    fi

    local reqdat
    reqdat=`mkreq "$1"` || return $?

    certdat=`signreq <(echo "$reqdat") "$2"` || return $?
    echo "$PKEY_BLOB" > privkey/$(<last_srl).key
}

cmd_revoke() {
    if [ $# -ne 1 ]; then
        echo "Exact 1 argument required." >&2
        return 1
    fi
    eval openssl ca -config \"$CONFIG_CA\" -revoke \"$1\" $CA_ARGS || return $?
    echo "Automatically call gencrl..." >&2
    cmd_gencrl
}

# getopt
getopt=`getopt -o "1g:k:h" -l "ca:,req:,ext:,noext,caarg:,san:,genkey:,key:" -n "$0" -- "$@"`
[ $? -ne 0 ] && exit 1
eval set -- "$getopt"
unset getopt

# process options
unset ONLY_V1
unset REQ_SAN
unset PKEY_BLOB
while true; do
    case "$1" in
        --ca)
            CONFIG_CA="$2"
            shift 2 ;;
        --req)
            CONFIG_REQ="$2"
            shift 2 ;;
        --ext)
            CONFIG_EXT="$2"
            shift 2 ;;
        -1|--noext)
            ONLY_V1=1
            shift ;;
        --caarg)
            CA_ARGS="$2"
            shift 2 ;;
        --san)
            if [ -z "$REQ_SAN" ]; then
                REQ_SAN="subjectAltName = $2"
            else
                REQ_SAN="$REQ_SAN,$2"
            fi
            shift 2 ;;
        -g|--genkey|-k|--key)
            if [ -z "$PKEY_BLOB" ]; then
                case $1 in
                    -g|--genkey)
                        PKEY_BLOB=`genpkey "$2"` ;;
                    -k|--key)
                        PKEY_BLOB=$(<"$2") ;;
                esac
                if [ -z "$PKEY_BLOB" ]; then
                    echo "$1 invalid." >&2
                fi
            else
                echo "$1 ignored." >&2
            fi
            shift 2 ;;
        -h)
            echo "$_usage"
            echo "$_help"
            exit 0 ;;
        --)
            shift; break ;;
        *)
            echo "Getopt internal error!" >&2
            exit 1 ;;
    esac
done
# Defaults
CONFIG_CA=${CONFIG_CA:-./ca.cnf}
CONFIG_REQ=${CONFIG_REQ:-$wd/conf/req.cnf}
CONFIG_EXT=${CONFIG_EXT:-./x509v3.cnf}
# Get realpath
CONFIG_CA=`realpath "$CONFIG_CA"`
CONFIG_REQ=`realpath "$CONFIG_REQ"`
CONFIG_EXT=`realpath "$CONFIG_EXT"`

if [ -z "$1" ]; then
    echo "$_usage"
    exit 0
fi
# Fetch and check command
cmd=$1
shift
if [ "`type -t cmd_$cmd`" != function ]; then
    echo "Unknown command $cmd." >&2
    exit 1
fi
cmd_$cmd "$@"
ret=$?
[ $ret -eq 0 ] && echo "Command succeeded!" >&2 || echo "Command failed." >&2
exit $ret

# vim: set et:
