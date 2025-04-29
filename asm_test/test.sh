#!/bin/bash

# Track failures globally
FAILED=0

# Allow some wiggle room for optimizer changes
BAD_BUFFER=2
GOOD_BUFFER=2

# Test different feature sets
function test_all() {
	cargo --quiet install cargo-show-asm@0.2.49 
	test_all_targets
	test_all_targets core_hint_black_box

	exit "${FAILED}"
}

# Test all the common architectures with their known good and bad values
function test_all_targets() {
	test "aarch64-unknown-linux-gnu"     2 14 ${@}
	test "i686-unknown-linux-gnu"        2 18 ${@}
	test "x86_64-unknown-linux-gnu"      2 15 ${@}
	test "arm-unknown-linux-gnueabi"     2 9  ${@}
	test "loongarch64-unknown-linux-gnu" 2 19 ${@}
	test "powerpc-unknown-linux-gnu"     2 27 ${@}
	test "powerpc64-unknown-linux-gnu"   3 22 ${@}
	test "powerpc64le-unknown-linux-gnu" 2 25 ${@}
	test "riscv64gc-unknown-linux-gnu"   2 17 ${@}
	test "s390x-unknown-linux-gnu"       2 13 ${@}
	test "wasm32-unknown-unknown"        2 11 ${@}
	test "thumbv7em-none-eabi"           2 10 ${@}
}

# Args:
# * The target name
# * The expected # of instructions for the bad case (optimizer defeated us)
# * The expected # of instructions for the good case (we beat the optimizer)
# * Any feature flags
#
# We take in both bad and good just to ensure there's no overlap.
function test() {
	local TARGET=$1
	local BAD=$(($2 + ${BAD_BUFFER}))
	local GOOD=$(($3 - ${GOOD_BUFFER}))
	shift 3
	local FEATURES=""

	# Build up the feature flags
	for F in "${@}"; do
		FEATURES+="--features=${F} "
	done

	# Make sure the good and bad ranges don't overlap
	if [ "${GOOD}" -le "${BAD}" ]; then
		echo "${TARGET} invalid params"
		exit 1
	fi

	# Ensure the target is available
	rustup -q target add "${TARGET}"

	# Build and capture the assembly
	catch INST INST_ERR env CARGO_TERM_QUIET=true cargo --quiet asm ${FEATURES} --target "${TARGET}" --simplify select_byte

	# Emit any cargo errors
	local STATUS=${?}
	if [ ${STATUS} -ne 0 ]; then 
		FAILED=1
		>&2 echo "${INST_ERR}"
		return
	fi

	# Check the instruction count
	local INST_COUNT="$(echo -n "${INST}" | wc -l)"
	if [ "${INST_COUNT}" -lt "${BAD}" ]; then
		FAILED=1
		echo "${TARGET}: Less than ${BAD} instructions (${INST_COUNT})"
		echo "${INST}"
	elif [ "${INST_COUNT}" -lt "${GOOD}" ]; then
		FAILED=1
		echo "${TARGET}: WARNING Less than ${GOOD} instructions (${INST_COUNT})"
		echo "Consider adjusting values"
		echo "${INST}"
	fi
}

# Capture both stderr and stdout
# https://stackoverflow.com/questions/11027679/capture-stdout-and-stderr-into-different-variables
function catch() {
    {
        IFS=$'\n' read -r -d '' "${1}";
        IFS=$'\n' read -r -d '' "${2}";
        (IFS=$'\n' read -r -d '' _ERRNO_; return ${_ERRNO_});
    } < <((printf '\0%s\0%d\0' "$(((({ shift 2; "${@}"; echo "${?}" 1>&3-; } | tr -d '\0' 1>&4-) 4>&2- 2>&1- | tr -d '\0' 1>&4-) 3>&1- | exit "$(cat)") 4>&1-)" "${?}" 1>&2) 2>&1)
}

test_all
