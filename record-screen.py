from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timedelta
from pathlib import Path


class ScreenRecorder:
    def __init__(self) -> None:
        self.process: subprocess.Popen[str] | None = None
        self.start_ts: float | None = None
        self.out_file: str | None = None

    def _select_region(self) -> tuple[int, int, int, int]:
        """Use slop to select a screen region."""
        result = subprocess.run(
            ["slop", "-f", "%x %y %w %h"],
            capture_output=True,
            text=True,
            check=True,
        )

        x, y, w, h = map(int, result.stdout.strip().split())

        # H.264 requires even dimensions
        w -= w % 2
        h -= h % 2

        return x, y, w, h

    def _ffmpeg_has_encoder(self, encoder: str) -> bool:
        """Check whether FFmpeg supports a specific encoder."""
        result = subprocess.run(
            ["ffmpeg", "-hide_banner", "-encoders"],
            capture_output=True,
            text=True,
        )
        return encoder in result.stdout

    def _video_encoder_args(self) -> list[str]:
        """
        Choose the best available video encoder dynamically.
        Returns FFmpeg arguments for video encoding.
        """

        # NVIDIA NVENC
        if self._ffmpeg_has_encoder("h264_nvenc"):
            print("Using NVIDIA NVENC encoder")
            return [
                "-c:v",
                "h264_nvenc",
                "-preset",
                "p5",
                "-cq",
                "23",
                "-pix_fmt",
                "yuv420p",
            ]

        # Intel Quick Sync
        if self._ffmpeg_has_encoder("h264_qsv"):
            print("Using Intel Quick Sync encoder")
            return [
                "-c:v",
                "h264_qsv",
                "-global_quality",
                "23",
                "-pix_fmt",
                "yuv420p",
            ]

        # VAAPI (Intel / AMD)
        if self._ffmpeg_has_encoder("h264_vaapi"):
            print("Using VAAPI encoder")
            return [
                "-vaapi_device",
                "/dev/dri/renderD128",
                "-vf",
                "format=nv12,hwupload",
                "-c:v",
                "h264_vaapi",
                "-qp",
                "23",
            ]

        # CPU fallback
        print("Using CPU libx264 encoder")
        return [
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "23",
            "-pix_fmt",
            "yuv420p",
        ]

    def start_recording(self, fps: int = 60) -> str:
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

        # Dynamic video encoder
        video_args = self._video_encoder_args()

        cmd = [
            "ffmpeg",
            "-y",
            # Better timestamps
            "-use_wallclock_as_timestamps",
            "1",
            "-fflags",
            "+genpts",
            # Video input
            "-video_size",
            f"{w}x{h}",
            "-framerate",
            str(fps),
            "-f",
            "x11grab",
            "-thread_queue_size",
            "1024",
            "-i",
            f":0.0+{x},{y}",
            # Audio input
            "-f",
            "pulse",
            "-thread_queue_size",
            "1024",
            "-i",
            audio_source,
            # Sync
            # "-vsync",
            # "1",
            "-fps_mode",
            "cfr",
            "-async",
            "1",
            # Video encoding
            *video_args,
            # Audio encoding
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            self.out_file,
        ]

        self.process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        self.start_ts = time.time()

        return self.out_file

    def is_recording(self) -> bool:
        proc = self.process
        return proc is not None and proc.poll() is None

    def elapsed_seconds(self) -> int:
        if not self.is_recording() or self.start_ts is None:
            return 0

        return int(time.time() - self.start_ts)

    def elapsed_time(self) -> str:
        return str(timedelta(seconds=self.elapsed_seconds()))

    def output_file(self) -> str | None:
        return self.out_file

    def stop_recording(self) -> bool:
        proc = self.process

        if proc is None or proc.poll() is not None:
            return False

        # Graceful stop - prevents missing last seconds
        if proc.stdin is not None:
            proc.stdin.write("q\n")
            proc.stdin.flush()

        proc.wait(timeout=15)

        self.process = None
        self.start_ts = None

        return True

    def recorded_duration(self) -> float:
        """Return actual saved file duration in seconds."""
        if self.out_file is None:
            return 0.0

        result = subprocess.check_output(
            [
                "ffprobe",
                "-v",
                "quiet",
                "-print_format",
                "json",
                "-show_format",
                self.out_file,
            ],
            text=True,
        )

        data = json.loads(result)
        return float(data["format"]["duration"])


if __name__ == "__main__":
    rec = ScreenRecorder()

    path = rec.start_recording()
    print(f"Started recording: {path}")
    print("Press Ctrl+C to stop.")

    try:
        while rec.is_recording():
            print(f"\rREC ● {rec.elapsed_time()}", end="", flush=True)
            time.sleep(1)

    except KeyboardInterrupt:
        # Clear the current terminal line and move to column 0
        print("\r\033[2K", end="", flush=True)

        print("Stopping recording...")

        rec.stop_recording()

        actual = rec.recorded_duration()

        print(f"Saved to: {path}")
        print(f"Recording Duration: {actual:.2f} seconds")
