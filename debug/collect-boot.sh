#!/system/bin/sh

KERNEL_VER=$(/system/bin/uname -r)
case "$KERNEL_VER" in
    6.18.*) ;;
    *) exit 0 ;;
esac
OUT_DIR=/data/local/tmp/logs
DURATION=280
mkdir -p "$OUT_DIR" || exit 1
KERNEL_LOG="$OUT_DIR/kernel_${KERNEL_VER}.log"
LOGCAT_LOG="$OUT_DIR/logcat_${KERNEL_VER}.log"
DEBUG_LOG="$OUT_DIR/collector_debug_${KERNEL_VER}.log"
UI_LOG="$OUT_DIR/ui_state_${KERNEL_VER}.log"
: > "$KERNEL_LOG"
: > "$LOGCAT_LOG"
: > "$DEBUG_LOG"
: > "$UI_LOG"
exec >> "$DEBUG_LOG" 2>&1
echo boot-collector > /proc/$$/comm
echo -15 > /proc/$$/oom_score_adj
renice -n -10 -p $$
echo "Collector start release=$KERNEL_VER pid=$$ date=$(date)"

flush_file()
{
    /system/bin/timeout -k 1 4 /system/bin/dd if=/dev/null of="$1" \
        oflag=append conv=notrunc,fsync status=none
}

flush_loop()
{
    echo boot-fsync > /proc/self/comm
    while true; do
        sleep 2
        flush_file "$1"
        FLUSH_RC=$?
        if [ "$FLUSH_RC" -ne 0 ]; then
            echo "fsync failed file=$1 rc=$FLUSH_RC uptime=$(cat /proc/uptime)"
        fi
    done
}

process_state()
{
    if [ -r "/proc/$1/status" ]; then
        echo "process pid=$1 name=$2"
        cat "/proc/$1/stat" "/proc/$1/wchan"
        cat "/proc/$1/io"
    else
        echo "process missing pid=$1 name=$2"
    fi
}

java_trace_loop()
{
    echo boot-java > /proc/self/comm
    sleep 50
    while true; do
        echo "Java traces uptime=$(cat /proc/uptime)"
        for TRACE_NAME in system_server com.android.systemui; do
            for TRACE_PID in $(pidof "$TRACE_NAME"); do
                echo "Java trace begin name=$TRACE_NAME pid=$TRACE_PID"
                /system/bin/timeout -k 1 8 /system/bin/debuggerd -j "$TRACE_PID"
                echo "Java trace end name=$TRACE_NAME pid=$TRACE_PID rc=$?"
            done
        done
        flush_file "$UI_LOG"
        sleep 15
    done
}

usb_state()
{
    echo "USB uptime=$(cat /proc/uptime) config=$(getprop sys.usb.config) state=$(getprop sys.usb.state) adbd=$(getprop init.svc.adbd) controller=$(getprop sys.usb.controller)"
    ls -l /sys/class/udc /sys/bus/platform/drivers/msm_eusb2_phy \
        /sys/bus/platform/drivers/eusb2-repeater
    for USB_PATH in /config/usb_gadget/g1/UDC /sys/class/udc/*/state; do
        echo "$USB_PATH"
        cat "$USB_PATH"
    done
    for USB_DEVICE in /sys/bus/platform/devices/88e3000.hsphy \
        /sys/bus/platform/devices/a600000.ssusb \
        /sys/bus/platform/devices/a600000.dwc3; do
        ls -ld "$USB_DEVICE/driver" "$USB_DEVICE"/supplier:*
    done
}

snapshot_loop()
{
    echo boot-ui > /proc/self/comm
    while true; do
        sleep 20
        echo "UI snapshot uptime=$(cat /proc/uptime) boot_completed=$(getprop sys.boot_completed)"
        cat /proc/bus/input/devices /proc/interrupts
        for UI_NAME in system_server com.android.systemui surfaceflinger \
            vendor.qti.hardware.display.composer-service; do
            for UI_PID in $(pidof "$UI_NAME"); do
                process_state "$UI_PID" "$UI_NAME"
            done
        done
        usb_state
        for UI_SERVICE in input "window policy" power "SurfaceFlinger --list"; do
            echo "dumpsys begin service=$UI_SERVICE uptime=$(cat /proc/uptime)"
            /system/bin/timeout -k 1 5 /system/bin/dumpsys -t 3 $UI_SERVICE
            echo "dumpsys end service=$UI_SERVICE rc=$? uptime=$(cat /proc/uptime)"
        done
        echo "dumpsys begin SystemUI uptime=$(cat /proc/uptime)"
        /system/bin/timeout -k 1 6 /system/bin/dumpsys -t 4 activity service \
            com.android.systemui/.SystemUIService
        echo "dumpsys end SystemUI rc=$? uptime=$(cat /proc/uptime)"
        flush_file "$UI_LOG"
    done
}

/system/bin/dmesg -w >> "$KERNEL_LOG" 2>&1 &
KERNEL_PID=$!
/system/bin/logcat -b all -v threadtime -v monotonic >> "$LOGCAT_LOG" 2>&1 &
LOGCAT_PID=$!
flush_loop "$KERNEL_LOG" &
KERNEL_FLUSH_PID=$!
flush_loop "$LOGCAT_LOG" &
LOGCAT_FLUSH_PID=$!
flush_loop "$DEBUG_LOG" &
DEBUG_FLUSH_PID=$!
snapshot_loop >> "$UI_LOG" 2>&1 &
UI_PID=$!
java_trace_loop >> "$UI_LOG" 2>&1 &
JAVA_PID=$!

cleanup()
{
    trap - EXIT TERM INT
    echo "Collector stopping uptime=$(cat /proc/uptime)"
    kill "$KERNEL_PID" "$LOGCAT_PID" "$KERNEL_FLUSH_PID" \
        "$LOGCAT_FLUSH_PID" "$DEBUG_FLUSH_PID" "$UI_PID" "$JAVA_PID" 2>/dev/null
    pkill -P "$KERNEL_FLUSH_PID" 2>/dev/null
    pkill -P "$LOGCAT_FLUSH_PID" 2>/dev/null
    pkill -P "$DEBUG_FLUSH_PID" 2>/dev/null
    pkill -P "$UI_PID" 2>/dev/null
    pkill -P "$JAVA_PID" 2>/dev/null
    flush_file "$KERNEL_LOG"
    flush_file "$LOGCAT_LOG"
    flush_file "$UI_LOG"
    echo "Collector finished uptime=$(cat /proc/uptime)"
    flush_file "$DEBUG_LOG"
}
trap cleanup EXIT
trap 'exit 0' TERM INT

ELAPSED=0
while [ "$ELAPSED" -lt "$DURATION" ]; do
    echo "<6>boot-collector: heartbeat pid=$$ dmesg=$KERNEL_PID logcat=$LOGCAT_PID uptime=$(cat /proc/uptime)" > /dev/kmsg
    echo "heartbeat uptime=$(cat /proc/uptime) boot_completed=$(getprop sys.boot_completed)"
    cat /proc/$$/cgroup /proc/$$/wchan
    flush_file "$DEBUG_LOG"
    process_state "$KERNEL_PID" dmesg
    process_state "$LOGCAT_PID" logcat
    for FLUSH_PID in "$KERNEL_FLUSH_PID" "$LOGCAT_FLUSH_PID" "$DEBUG_FLUSH_PID"; do
        process_state "$FLUSH_PID" fsync-worker
    done
    wc -c "$KERNEL_LOG" "$LOGCAT_LOG" "$UI_LOG"
    if ! kill -0 "$KERNEL_PID" 2>/dev/null; then
        wait "$KERNEL_PID"
        echo "dmesg exited rc=$?; restarting"
        /system/bin/dmesg -w >> "$KERNEL_LOG" 2>&1 &
        KERNEL_PID=$!
    fi
    if ! kill -0 "$LOGCAT_PID" 2>/dev/null; then
        wait "$LOGCAT_PID"
        echo "logcat exited rc=$?; restarting"
        /system/bin/logcat -b all -v threadtime -v monotonic >> "$LOGCAT_LOG" 2>&1 &
        LOGCAT_PID=$!
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done
