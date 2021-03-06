#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

FILES='
arch/x86/include/asm/inat_types.h
arch/x86/include/asm/orc_types.h
arch/x86/include/asm/emulate_prefix.h
arch/x86/lib/x86-opcode-map.txt
arch/x86/tools/gen-insn-attr-x86.awk
'

check()
{
	local file=$1

	diff ../$file ../../$file > /dev/null ||
		echo "Warning: synced file at 'tools/objtool/$file' differs from latest kernel version at '$file'"
}

if [ ! -d ../../kernel ] || [ ! -d ../../tools ] || [ ! -d ../objtool ]; then
	exit 0
fi

for i in $FILES; do
  check $i
done

check arch/x86/include/asm/inat.h     '-I "^#include [\"<]\(asm/\)*inat_types.h[\">]"'
check arch/x86/include/asm/insn.h     '-I "^#include [\"<]\(asm/\)*inat.h[\">]"'
check arch/x86/lib/inat.c             '-I "^#include [\"<]\(../include/\)*asm/insn.h[\">]"'
check arch/x86/lib/insn.c             '-I "^#include [\"<]\(../include/\)*asm/in\(at\|sn\).h[\">]" -I "^#include [\"<]\(../include/\)*asm/emulate_prefix.h[\">]"'

