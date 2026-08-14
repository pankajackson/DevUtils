from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path


class RecorderError(Exception):
    """Base exception for screen recorder errors."""


class DependencyError(RecorderError):
    """Raised when a required external dependency is missing."""


class ScreenRecorder:
    def __init__(self) -> None:
        self.process: subprocess.Popen[str] | None = None
        self.start_ts: float | None = None
        self.out_file: str | None = None

        self._check_dependencies()

    # ------------------------------------------------------------------
    # Dependency checks
    # ------------------------------------------------------------------

    def _check_dependencies(self) -> None:
        """Check that all required external programs are installed."""

        required = {
            "ffmpeg": "FFmpeg is required for screen recording.",
            "ffprobe": "FFprobe is required for reading recording duration.",
            "slop": "slop is required for selecting the recording area.",
            "pactl": "pactl is required for microphone/audio capture.",
        }

        missing: list[str] = []

        for command, description in required.items():
            if shutil.which(command) is None:
                missing.append(f"  {command}: {description}")

        if missing:
            message = (
                "Missing required dependencies:\n\n" + "\n".join(missing) + "\n\n"
                "Please install the missing package(s) and try again."
            )

            raise DependencyError(message)

    # ------------------------------------------------------------------
    # Region selection
    # ------------------------------------------------------------------

    def _select_region(self) -> tuple[int, int, int, int]:
        """Use slop to select a screen region."""

        try:
            result = subprocess.run(
                ["slop", "-f", "%x %y %w %h"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise RecorderError(
                "Screen area selection was cancelled or failed."
            ) from exc
        except OSError as exc:
            raise RecorderError(f"Failed to execute slop: {exc}") from exc

        output = result.stdout.strip()

        if not output:
            raise RecorderError("No recording area was selected.")

        try:
            x, y, w, h = map(int, output.split())
        except ValueError as exc:
            raise RecorderError(f"Invalid region returned by slop: {output!r}") from exc

        if w <= 0 or h <= 0:
            raise RecorderError(f"Invalid recording dimensions: {w}x{h}")

        # H.264 requires even dimensions.
        w -= w % 2
        h -= h % 2

        if w <= 0 or h <= 0:
            raise RecorderError(
                f"Recording area is too small after adjustment: {w}x{h}"
            )

        return x, y, w, h

    # ------------------------------------------------------------------
    # FFmpeg encoder detection
    # ------------------------------------------------------------------

    def _ffmpeg_has_encoder(self, encoder: str) -> bool:
        """Check whether FFmpeg supports a specific encoder."""

        try:
            result = subprocess.run(
                [
                    "ffmpeg",
                    "-hide_banner",
                    "-encoders",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            return False

        for line in result.stdout.splitlines():
            stripped = line.strip()

            if not stripped or stripped.startswith("------"):
                continue

            # Encoder name is normally the second whitespace-separated
            # field in an FFmpeg encoder listing.
            parts = stripped.split()

            if len(parts) >= 2 and parts[1] == encoder:
                return True

        return False

    def _video_encoder_args(self) -> list[str]:
        """
        Select the best available encoder dynamically.

        Priority:

        1. NVIDIA NVENC
        2. Intel Quick Sync
        3. VAAPI
        4. CPU libx264
        """

        # --------------------------------------------------------------
        # NVIDIA NVENC
        # --------------------------------------------------------------

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

        # --------------------------------------------------------------
        # Intel Quick Sync
        # --------------------------------------------------------------

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

        # --------------------------------------------------------------
        # VAAPI (Intel / AMD)
        # --------------------------------------------------------------

        vaapi_device = Path("/dev/dri/renderD128")

        if vaapi_device.exists() and self._ffmpeg_has_encoder("h264_vaapi"):
            print(f"Using VAAPI encoder ({vaapi_device})")

            return [
                "-vaapi_device",
                str(vaapi_device),
                "-vf",
                "format=nv12,hwupload",
                "-c:v",
                "h264_vaapi",
                "-qp",
                "23",
            ]

        # --------------------------------------------------------------
        # CPU fallback
        # --------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Audio
    # ------------------------------------------------------------------

    def _get_audio_source(self) -> str:
        """Get the default PulseAudio/PipeWire source."""

        try:
            result = subprocess.run(
                ["pactl", "get-default-source"],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise RecorderError(
                "Could not determine the default audio source.\n"
                "Make sure PulseAudio/PipeWire is running."
            ) from exc
        except OSError as exc:
            raise RecorderError(f"Failed to execute pactl: {exc}") from exc

        source = result.stdout.strip()

        if not source:
            raise RecorderError("No default audio source was found.")

        return source

    # ------------------------------------------------------------------
    # Start recording
    # ------------------------------------------------------------------

    def start_recording(self, fps: int = 60) -> str:
        """Start a new screen recording."""

        if self.is_recording():
            raise RuntimeError("Recording already in progress.")

        if fps <= 0:
            raise ValueError("FPS must be greater than zero.")

        x, y, w, h = self._select_region()

        out_dir = Path.home() / "Videos" / "Recordings"
        out_dir.mkdir(parents=True, exist_ok=True)

        self.out_file = str(
            out_dir / f"recording-{datetime.now():%Y-%m-%d_%H-%M-%S}.mkv"
        )

        audio_source = self._get_audio_source()

        video_args = self._video_encoder_args()

        cmd = [
            "ffmpeg",
            "-y",
            # ----------------------------------------------------------
            # Timestamp handling
            # ----------------------------------------------------------
            "-use_wallclock_as_timestamps",
            "1",
            "-fflags",
            "+genpts",
            # ----------------------------------------------------------
            # Video input
            # ----------------------------------------------------------
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
            # ----------------------------------------------------------
            # Audio input
            # ----------------------------------------------------------
            "-f",
            "pulse",
            "-thread_queue_size",
            "1024",
            "-i",
            audio_source,
            # ----------------------------------------------------------
            # Frame synchronization
            # ----------------------------------------------------------
            "-fps_mode",
            "cfr",
            # ----------------------------------------------------------
            # Video encoder
            # ----------------------------------------------------------
            *video_args,
            # ----------------------------------------------------------
            # Audio encoder
            # ----------------------------------------------------------
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            # ----------------------------------------------------------
            # Output
            # ----------------------------------------------------------
            self.out_file,
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            self.process = None

            raise RecorderError(f"Failed to start FFmpeg: {exc}") from exc

        # Give FFmpeg a moment to initialize and detect immediate errors.
        time.sleep(0.2)

        if self.process.poll() is not None:
            stderr = ""

            if self.process.stderr is not None:
                stderr = self.process.stderr.read().strip()

            self.process = None

            if stderr:
                raise RecorderError("FFmpeg failed to start:\n\n" f"{stderr}")

            raise RecorderError("FFmpeg exited unexpectedly while starting.")

        self.start_ts = time.time()

        return self.out_file

    # ------------------------------------------------------------------
    # Recording status
    # ------------------------------------------------------------------

    def is_recording(self) -> bool:
        """Return True if FFmpeg is currently recording."""

        proc = self.process

        return proc is not None and proc.poll() is None

    def elapsed_seconds(self) -> int:
        """Return elapsed recording time in seconds."""

        if not self.is_recording() or self.start_ts is None:
            return 0

        return max(0, int(time.time() - self.start_ts))

    def elapsed_time(self) -> str:
        """Return elapsed time as HH:MM:SS."""

        return str(timedelta(seconds=self.elapsed_seconds()))

    def output_file(self) -> str | None:
        """Return the current output file."""

        return self.out_file

    # ------------------------------------------------------------------
    # Stop recording
    # ------------------------------------------------------------------

    def stop_recording(self) -> bool:
        """Gracefully stop FFmpeg."""

        proc = self.process

        if proc is None:
            return False

        if proc.poll() is not None:
            self.process = None
            self.start_ts = None

            return False

        try:
            # FFmpeg's 'q' command performs a graceful shutdown and
            # flushes encoders/container data.
            if proc.stdin is not None:
                proc.stdin.write("q\n")
                proc.stdin.flush()

            proc.wait(timeout=15)

        except subprocess.TimeoutExpired as exc:
            proc.kill()

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

            self.process = None
            self.start_ts = None

            raise RecorderError(
                "FFmpeg did not stop gracefully within 15 seconds."
            ) from exc

        finally:
            if proc.stdin is not None:
                proc.stdin.close()

        self.process = None
        self.start_ts = None

        return True

    # ------------------------------------------------------------------
    # Actual file duration
    # ------------------------------------------------------------------

    def recorded_duration(self) -> float:
        """Return actual saved file duration in seconds."""

        if self.out_file is None:
            return 0.0

        output_path = Path(self.out_file)

        if not output_path.exists():
            raise RecorderError(f"Recording file does not exist: {output_path}")

        try:
            result = subprocess.run(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-print_format",
                    "json",
                    "-show_format",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            error = exc.stderr.strip()

            raise RecorderError(
                "FFprobe failed to read the recording."
                + (f"\n\n{error}" if error else "")
            ) from exc

        try:
            data = json.loads(result.stdout)
            duration = data["format"]["duration"]

            return float(duration)

        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RecorderError("FFprobe returned an invalid duration.") from exc


# ======================================================================
# Main
# ======================================================================


def main() -> int:
    try:
        rec = ScreenRecorder()

        path = rec.start_recording()

        print(f"Started recording: {path}")
        print("Press Ctrl+C to stop.")

        try:
            while rec.is_recording():
                print(
                    f"\rREC ● {rec.elapsed_time()}",
                    end="",
                    flush=True,
                )

                time.sleep(1)

        except KeyboardInterrupt:
            # Erase the timer line.
            print("\r\033[2K", end="", flush=True)

            print("Stopping recording...")

            rec.stop_recording()

            actual = rec.recorded_duration()

            print(f"Saved to: {path}")
            print(f"Recording Duration: {actual:.2f} seconds")

            return 0

        # FFmpeg stopped unexpectedly.
        print("\r\033[2K", end="", flush=True)

        print("FFmpeg stopped unexpectedly.")

        if rec.output_file() is not None:
            print(f"Output file: {rec.output_file()}")

        return 1

    except DependencyError as exc:
        print(f"Error: {exc}", file=sys.stderr)

        return 1

    except RecorderError as exc:
        print(f"Error: {exc}", file=sys.stderr)

        return 1

    except KeyboardInterrupt:
        # Handles Ctrl+C during slop or before recording starts.
        print("\nOperation cancelled.")

        return 130

    except FileNotFoundError as exc:
        print(
            f"Error: Required executable was not found: {exc}",
            file=sys.stderr,
        )

        return 1

    except PermissionError as exc:
        print(
            f"Error: Permission denied: {exc}",
            file=sys.stderr,
        )

        return 1

    except Exception as exc:
        print(
            f"Unexpected error: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )

        return 2


if __name__ == "__main__":
    sys.exit(main())
