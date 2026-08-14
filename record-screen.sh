#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$HOME/Videos/Recordings"
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/recording-$(date +%F_%H-%M-%S).mkv"

echo "Select an area with the mouse..."

GEOM=$(slop -f "%x %y %w %h")
[ -z "$GEOM" ] && { echo "Selection cancelled"; exit 1; }

read -r X Y W H <<< "$GEOM"

# Make dimensions even for H.264
W=$((W - W % 2))
H=$((H - H % 2))

echo "Recording area: ${W}x${H} at (${X},${Y})"
echo "Output: $OUT_FILE"
echo "Press Ctrl+C to stop recording."

AUDIO_SOURCE=$(pactl get-default-source)

ffmpeg \
    -video_size "${W}x${H}" \
    -framerate 60 \
    -f x11grab \
    -i ":0.0+${X},${Y}" \
    -f pulse \
    -i "$AUDIO_SOURCE" \
    -c:v libx264 \
    -preset veryfast \
    -crf 23 \
    -pix_fmt yuv420p \
    -c:a aac \
    -b:a 192k \
    "$OUT_FILE"

echo "Saved to: $OUT_FILE"