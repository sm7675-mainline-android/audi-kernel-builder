#!/system/bin/sh

brightness=/sys/class/backlight/panel0-backlight/brightness
remaining=75
while [ ! -w "$brightness" ] || [ ! -c /dev/dri/card0 ]; do
    [ "$remaining" -gt 0 ] || break
    /system/bin/sleep 0.2 || break
    remaining=$((remaining - 1))
done

exec /system/bin/recovery "$@"
