#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
set -eu

LC_ALL=C
export LC_ALL

artifact=${1:?"usage: validate_kpm.sh ARTIFACT READELF NM VERSION"}
readelf_tool=${2:?"usage: validate_kpm.sh ARTIFACT READELF NM VERSION"}
nm_tool=${3:?"usage: validate_kpm.sh ARTIFACT READELF NM VERSION"}
expected_version=${4:?"usage: validate_kpm.sh ARTIFACT READELF NM VERSION"}

fail()
{
    echo "error: $*" >&2
    exit 1
}

[ -f "$artifact" ] || fail "KPM artifact not found: $artifact"
command -v "$readelf_tool" >/dev/null 2>&1 || \
    fail "readelf tool not found: $readelf_tool"
command -v "$nm_tool" >/dev/null 2>&1 || \
    fail "nm tool not found: $nm_tool"

elf_header=$($readelf_tool -h "$artifact")
section_headers=$($readelf_tool -SW "$artifact")
symbols=$($readelf_tool -Ws "$artifact")
relocation_dump=$($readelf_tool -rW "$artifact")
info_dump=$($readelf_tool -p .kpm.info "$artifact")

printf '%s\n' "$elf_header" | grep -Eq \
    'Class:[[:space:]]+ELF64' || fail "KPM is not ELF64"
printf '%s\n' "$elf_header" | grep -Eq \
    'Data:.*little endian' || fail "KPM is not little-endian"
printf '%s\n' "$elf_header" | grep -Eq \
    'Type:[[:space:]]+REL ' || fail "KPM is not relocatable ELF"
printf '%s\n' "$elf_header" | grep -Eq \
    'Machine:[[:space:]]+AArch64' || fail "KPM is not AArch64"

has_section()
{
    printf '%s\n' "$section_headers" | awk -v wanted="$1" '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == wanted) {
                    found = 1
                }
            }
        }
        END { exit found ? 0 : 1 }
    '
}

section_size()
{
    printf '%s\n' "$section_headers" | awk -v wanted="$1" '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == wanted) {
                    print $(i + 4)
                    exit
                }
            }
        }
    '
}

for section in .kpm.info .kpm.ctl0 .kpm.exit .kpm.init; do
    has_section "$section" || fail "missing required section: $section"
done

info_size=$(section_size .kpm.info | sed 's/^0*//')
[ -n "$info_size" ] || fail ".kpm.info must not be empty"
info_strings=$(printf '%s\n' "$info_dump" | sed -n \
    's/^[[:space:]]*\[[^]]*\][[:space:]]*//p')
printf '%s\n' "$info_strings" | grep -Fqx 'name=BrickGuard' || \
    fail ".kpm.info has the wrong module name"
printf '%s\n' "$info_strings" | grep -Fqx "version=$expected_version" || \
    fail ".kpm.info has the wrong module version"
printf '%s\n' "$info_strings" | grep -Fqx 'license=GPL v2' || \
    fail ".kpm.info has the wrong license"

for section in .kpm.ctl0 .kpm.exit .kpm.init; do
    size=$(section_size "$section" | sed 's/^0*//')
    [ "$size" = "8" ] || fail "$section must contain one 64-bit pointer"
done

for section in .kpm.ctl0 .kpm.exit .kpm.init; do
    relocation_section=".rela$section"
    has_section "$relocation_section" || \
        fail "missing entry relocation section: $relocation_section"
    size=$(section_size "$relocation_section" | sed 's/^0*//')
    [ "$size" = "18" ] || \
        fail "$relocation_section must contain one Elf64_Rela entry"

    entry_record=$(printf '%s\n' "$relocation_dump" | \
        awk -v wanted="$relocation_section" '
            BEGIN { quoted = sprintf("%c%s%c", 39, wanted, 39) }
            $1 == "Relocation" && $2 == "section" {
                active = ($3 == quoted)
                next
            }
            active && $1 ~ /^[[:xdigit:]]+$/ &&
                $2 ~ /^[[:xdigit:]]+$/ {
                print $1 ":" $3 ":" $5
                exit
            }
        ')
    entry_offset=${entry_record%%:*}
    entry_rest=${entry_record#*:}
    entry_relocation=${entry_rest%%:*}
    entry_target=${entry_rest#*:}
    entry_offset=$(printf '%s\n' "$entry_offset" | sed 's/^0*//')
    [ -z "$entry_offset" ] || \
        fail "$relocation_section must relocate offset zero"
    [ "$entry_relocation" = "R_AARCH64_ABS64" ] || \
        fail "$relocation_section must use R_AARCH64_ABS64"
    [ "$entry_target" = ".text" ] || \
        fail "$relocation_section must target local .text"
done

for section in .dynamic .dynsym .dynstr; do
    if has_section "$section"; then
        fail "dynamic ELF section is not supported: $section"
    fi
done

if printf '%s\n' "$symbols" | grep -Eq '[[:space:]]COM[[:space:]]'; then
    fail "COMMON symbols are not supported"
fi

if printf '%s\n' "$symbols" | grep -Eq \
    '__aarch64_|__atomic_|__sync_'; then
    fail "compiler runtime symbol is not supported"
fi

expected_undefined='compat_copy_to_user
hook_wrap
kallsyms_lookup_name
kpm_exit_veto_supported
printk'
actual_undefined=$($nm_tool --undefined-only --format=posix "$artifact" | \
    awk '{ print $1 }' | sort -u)

if [ "$actual_undefined" != "$expected_undefined" ]; then
    echo "error: unexpected KPM undefined-symbol set" >&2
    echo "expected:" >&2
    printf '%s\n' "$expected_undefined" >&2
    echo "actual:" >&2
    printf '%s\n' "$actual_undefined" >&2
    exit 1
fi

relocations=$(printf '%s\n' "$relocation_dump" | awk '
    $1 ~ /^[[:xdigit:]]+$/ && $2 ~ /^[[:xdigit:]]+$/ { print $3 }
' | sort -u)

while IFS= read -r relocation; do
    [ -n "$relocation" ] || continue
    case "$relocation" in
        R_AARCH64_NONE|R_AARCH64_ABS64|R_AARCH64_ABS32|R_AARCH64_ABS16|\
        R_AARCH64_PREL64|R_AARCH64_PREL32|R_AARCH64_PREL16|\
        R_AARCH64_MOVW_UABS_G0_NC|R_AARCH64_MOVW_UABS_G0|\
        R_AARCH64_MOVW_UABS_G1_NC|R_AARCH64_MOVW_UABS_G1|\
        R_AARCH64_MOVW_UABS_G2_NC|R_AARCH64_MOVW_UABS_G2|\
        R_AARCH64_MOVW_UABS_G3|R_AARCH64_MOVW_SABS_G0|\
        R_AARCH64_MOVW_SABS_G1|R_AARCH64_MOVW_SABS_G2|\
        R_AARCH64_MOVW_PREL_G0_NC|R_AARCH64_MOVW_PREL_G0|\
        R_AARCH64_MOVW_PREL_G1_NC|R_AARCH64_MOVW_PREL_G1|\
        R_AARCH64_MOVW_PREL_G2_NC|R_AARCH64_MOVW_PREL_G2|\
        R_AARCH64_MOVW_PREL_G3|R_AARCH64_LD_PREL_LO19|\
        R_AARCH64_ADR_PREL_LO21|R_AARCH64_ADR_PREL_PG_HI21_NC|\
        R_AARCH64_ADR_PREL_PG_HI21|R_AARCH64_ADD_ABS_LO12_NC|\
        R_AARCH64_LDST8_ABS_LO12_NC|R_AARCH64_LDST16_ABS_LO12_NC|\
        R_AARCH64_LDST32_ABS_LO12_NC|R_AARCH64_LDST64_ABS_LO12_NC|\
        R_AARCH64_LDST128_ABS_LO12_NC|R_AARCH64_TSTBR14|\
        R_AARCH64_CONDBR19|R_AARCH64_JUMP26|R_AARCH64_CALL26)
            ;;
        *)
            fail "KernelPatch loader does not support relocation: $relocation"
            ;;
    esac
done <<EOF
$relocations
EOF

echo "Validated: $artifact"
