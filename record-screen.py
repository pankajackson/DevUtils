import os
import signal
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path


class ScreenRecorder:
    def __init__(self):
        self.process = None
        self.start_ts = None
        self.out_file = None

    def _select_region(self):
        result = subprocess.run(
            ["slop", "-f", "%x %y %w %h"],
            capture_output=True,
            text=True,
            check=True,
        )
        x, y, w, h = map(int, result.stdout.strip().split())

        # Make dimensions even for H.264
        w -= w % 2
        h -= h % 2

        return x, y, w, h

    def start_recording(self, fps=60):
        if self.is_recording():
            raise RuntimeError("Recording already in progress")

        x, y, w, h = self._select_region()

        out_dir = Path.home() / "Videos" / "Recordings"
        out_dir.mkdir(parents=True, exist_ok=True)

        self.out_file = str(
            out_dir / f"recording-{datetime.now():%Y-%m-%d_%H-%M-%S}.mkv"
        )

        audio_source = subprocess.check_output(
            ["pactl", "get-default-source"],
            text=True,
        ).strip()

        cmd = [
            "ffmpeg",
            "-y",
            "-video_size",
            f"{w}x{h}",
            "-framerate",
            str(fps),
            "-f",
            "x11grab",
            "-i",
            f":0.0+{x},{y}",
            "-f",
            "pulse",
            "-i",
            audio_source,
            "-c:v",
            "h264_nvenc",  # use NVIDIA GPU encoder
            "-preset",
            "p5",
            "-cq",
            "23",
            "-pix_fmt",
            "yuv420p",
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            self.out_file,
        ]

        self.process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        self.start_ts = time.time()
        return self.out_file

    def is_recording(self):
        return self.process is not None and self.process.poll() is None

    def elapsed_seconds(self):
        if not self.is_recording():
            return 0
        return int(time.time() - self.start_ts)

    def elapsed_time(self):
        return str(timedelta(seconds=self.elapsed_seconds()))

    def output_file(self):
        return self.out_file

    def stop_recording(self):
        if not self.is_recording():
            return False

        # Graceful stop
        self.process.send_signal(signal.SIGINT)
        self.process.wait(timeout=10)

        self.process = None
        self.start_ts = None
        return True


if __name__ == "__main__":
    rec = ScreenRecorder()

    path = rec.start_recording()
    print(f"Started recording: {path}")

    try:
        while rec.is_recording():
            print(f"Recording... {rec.elapsed_time()}", end="\r")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        rec.stop_recording()
        print(f"Saved to: {path}")
