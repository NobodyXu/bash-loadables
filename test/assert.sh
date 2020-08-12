assert() {
    if ! eval "$1"; then
        echo "$1 failed!" >&2
    fi
}
