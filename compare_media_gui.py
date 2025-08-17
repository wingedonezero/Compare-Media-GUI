import dearpygui.dearpygui as dpg
import subprocess
import json
import hashlib
import os
import threading
import queue
import tempfile

# --- Core Hashing & Info Functions ---

def check_ffmpeg_installed():
    """
    Checks if ffmpeg, ffprobe, and mkvextract are installed and accessible in the system's PATH.
    """
    try:
        subprocess.run(["ffmpeg", "-version"], capture_output=True, text=True, check=True)
        subprocess.run(["ffprobe", "-version"], capture_output=True, text=True, check=True)
        subprocess.run(["mkvextract", "--version"], capture_output=True, text=True, check=True)
        return True, None
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        tool = "mkvextract" if "mkvextract" in str(e) else "ffmpeg/ffprobe"
        return False, f"FATAL ERROR: {tool} not found in your system's PATH."

def get_stream_info(filepath, entries="streams"):
    """
    Uses ffprobe to extract detailed information about streams in a media file.
    """
    if not os.path.exists(filepath):
        return None, f"Error: File not found at '{filepath}'"

    command = [
        "ffprobe", "-v", "quiet", "-print_format", "json", f"-show_{entries}", filepath
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout).get(entries, []), None
    except subprocess.CalledProcessError as e:
        return None, f"ffprobe error: {e.stderr}"
    except json.JSONDecodeError:
        return None, "Error: Failed to parse ffprobe JSON output."

def get_stream_hash_copied(filepath, stream_index):
    """
    Generates an MD5 hash by performing a "stream copy".
    """
    command = [
        "ffmpeg", "-v", "error", "-i", filepath, "-map", f"0:{stream_index}",
        "-c", "copy", "-f", "hash", "-hash", "MD5", "-"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        hash_line = result.stdout.strip()
        if hash_line.startswith("MD5="):
            return hash_line.split("=")[1], None
        return None, "Error: Could not find MD5 hash in ffmpeg output."
    except subprocess.CalledProcessError as e:
        return None, f"ffmpeg error: {e.stderr}"

def get_stream_hash_decoded(filepath, stream_index):
    """
    Generates an MD5 hash by fully decoding the stream.
    """
    command = [
        "ffmpeg", "-v", "error", "-i", filepath, "-map", f"0:{stream_index}",
        "-f", "hash", "-hash", "MD5", "-"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        hash_line = result.stdout.strip()
        if hash_line.startswith("MD5="):
            return hash_line.split("=")[1], None
        return None, "Error: Could not find MD5 hash in ffmpeg output."
    except subprocess.CalledProcessError as e:
        return None, f"ffmpeg error: {e.stderr}"

def get_raw_stream_hash_in_memory(filepath, stream_index, codec_name):
    """
    Extracts a raw stream via FFmpeg's "dumb" demuxer, pipes it to memory,
    and calculates its MD5 hash. This ignores all container-level timing.
    """
    codec_to_format_map = {
        'truehd': 'truehd', 'ac3': 'ac3', 'dts': 'dts', 'aac': 'adts',
        'flac': 'flac', 'opus': 'opus', 'vorbis': 'ogg', 'h264': 'h264',
        'hevc': 'hevc', 'mpeg2video': 'mpeg2video', 'subrip': 'srt',
        'ass': 'ass', 'dvd_subtitle': 'vobsub',
        'pcm_s16le': 's16le', 'pcm_s24le': 's24le', 'pcm_s32le': 's32le'
    }

    raw_format = codec_to_format_map.get(codec_name)
    if not raw_format:
        return None, f"Unsupported codec '{codec_name}' for raw extraction."

    command = [
        "ffmpeg", "-v", "error", "-i", filepath, "-map", f"0:{stream_index}",
        "-c", "copy", "-f", raw_format, "-"
    ]

    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout_data, stderr_data = process.communicate()

        if process.returncode != 0:
            return None, f"ffmpeg error during raw extraction: {stderr_data.decode()}"

        hasher = hashlib.md5()
        hasher.update(stdout_data)
        return hasher.hexdigest(), None

    except Exception as e:
        return None, f"An error occurred during in-memory hashing: {e}"

def get_mkvextract_hash(filepath, stream_index):
    """
    Extracts a stream using mkvextract to a temporary file and hashes it.
    This method *applies* the container delay. The stream_index corresponds
    to the Track ID from mkvmerge/ffprobe.
    """
    temp_dir = tempfile.gettempdir()
    temp_filename = os.path.join(temp_dir, f"temp_stream_{stream_index}")

    command = ["mkvextract", "tracks", filepath, f"{stream_index}:{temp_filename}"]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        hasher = hashlib.md5()
        with open(temp_filename, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)

        return hasher.hexdigest(), None

    except subprocess.CalledProcessError as e:
        return None, f"mkvextract error: {e.stderr}"
    except FileNotFoundError:
        return None, "The temporary file was not created by mkvextract."
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

# --- Comparison & Info Logic ---

def run_full_comparison_threaded(hash_function, method_name, file1_path, file2_path, progress_queue, result_queue, stream_type_filter=None):
    """
    The main comparison logic for file comparison, run in a separate thread.
    Can optionally filter to only compare streams of a specific type.
    """
    report = []

    all_streams1, err1 = get_stream_info(file1_path)
    if err1:
        report.append(err1)
        result_queue.put(report)
        return

    all_streams2, err2 = get_stream_info(file2_path)
    if err2:
        report.append(err2)
        result_queue.put(report)
        return

    if stream_type_filter:
        streams1 = [s for s in all_streams1 if s.get('codec_type') == stream_type_filter]
        streams2 = [s for s in all_streams2 if s.get('codec_type') == stream_type_filter]
        report.append(f"Comparing all individual '{stream_type_filter}' streams.")
    else:
        streams1 = all_streams1
        streams2 = all_streams2
        report.append("Comparing all streams.")

    report.append(f"File 1: {os.path.basename(file1_path)} ({len(streams1)} matching streams found)")
    report.append(f"File 2: {os.path.basename(file2_path)} ({len(streams2)} matching streams found)")
    report.append(f"Method: {method_name}")
    report.append("-" * 60)

    if not streams1 or not streams2:
        report.append("No streams of the specified type found in one or both files.")
        result_queue.put(report)
        return

    total_streams_to_process = len(streams1) + len(streams2)
    processed_streams = 0

    stream_details_2 = {}
    for stream2 in streams2:
        processed_streams += 1
        progress_queue.put(processed_streams / total_streams_to_process)

        s2_index = stream2['index']
        s2_codec_type = stream2.get('codec_type', 'N/A')
        s2_codec_name = stream2.get('codec_name', 'N/A')

        current_hash_func = hash_function

        if method_name == "Raw In-Memory Hash":
            s2_hash, err = get_raw_stream_hash_in_memory(file2_path, s2_index, s2_codec_name)
        else:
            if method_name in ["Full Decode", "Streamhash Muxer"] and s2_codec_type not in ['video', 'audio']:
                current_hash_func = get_stream_hash_copied
            s2_hash, err = current_hash_func(file2_path, s2_index)

        stream_details_2[s2_index] = {
            "hash": s2_hash if not err else f"Error: {err}",
            "type": s2_codec_type,
            "codec": s2_codec_name,
            "matched": False
        }

    matched_streams_1 = set()
    stream_details_1 = {}
    report.append("--- Detailed Comparison ---")
    for stream1 in streams1:
        processed_streams += 1
        progress_queue.put(processed_streams / total_streams_to_process)

        s1_index = stream1['index']
        s1_codec = stream1.get('codec_name', 'N/A')
        s1_type = stream1.get('codec_type', 'N/A')

        report.append(f"\n[File 1] Stream #{s1_index} ({s1_type.upper()}, {s1_codec})")

        current_hash_func = hash_function
        note = ""

        if method_name == "Raw In-Memory Hash":
            s1_hash, err = get_raw_stream_hash_in_memory(file1_path, s1_index, s1_codec)
        else:
            if method_name in ["Full Decode", "Streamhash Muxer"] and s1_type not in ['video', 'audio']:
                current_hash_func = get_stream_hash_copied
                note = f"  - NOTE: Non-AV stream. Using fast copy hash instead."
            s1_hash, err = current_hash_func(file1_path, s1_index)

        stream_details_1[s1_index] = { "hash": s1_hash if not err else f"HASH ERROR: {err}" }

        if note: report.append(note)
        if err:
            report.append(f"  - HASH ERROR: {err}")
            continue

        report.append(f"  - Hash (MD5): {s1_hash}")

        found_in_file2 = False
        for s2_index, s2_details in stream_details_2.items():
            if s1_hash == s2_details['hash']:
                report.append(f"  - MATCH: Identical to File 2, Stream #{s2_index} ({s2_details['type'].upper()}, {s2_details['codec']})")
                found_in_file2 = True
                stream_details_2[s2_index]['matched'] = True
                matched_streams_1.add(s1_index)
                break

        if not found_in_file2: report.append("  - NO MATCH found in File 2.")

    report.append("\n" + "-" * 60)
    report.append("--- Summary of Unmatched Streams ---")

    unmatched_in_1_found = False
    for stream1 in streams1:
        if stream1['index'] not in matched_streams_1:
            s1_index = stream1['index']
            s1_hash_info = stream_details_1.get(s1_index, {}).get('hash', 'N/A')
            report.append(f"[File 1] Unmatched: Stream #{s1_index} ({stream1.get('codec_type', 'N/A').upper()}, {stream1.get('codec_name', 'N/A')})")
            report.append(f"  - Hash (MD5): {s1_hash_info}")
            unmatched_in_1_found = True
    if not unmatched_in_1_found and streams1:
        report.append(f"[File 1] All '{stream_type_filter or 'streams'}' streams found a match in File 2.")

    report.append("")

    unmatched_in_2_found = False
    for s2_index, s2_details in stream_details_2.items():
        if not s2_details['matched']:
            s2_hash_info = s2_details.get('hash', 'N/A')
            report.append(f"[File 2] Unmatched: Stream #{s2_index} ({s2_details['type'].upper()}, {s2_details['codec']})")
            report.append(f"  - Hash (MD5): {s2_hash_info}")
            unmatched_in_2_found = True
    if not unmatched_in_2_found and streams2:
        report.append(f"[File 2] All '{stream_type_filter or 'streams'}' streams were matched by a stream in File 1.")

    result_queue.put(report)

def run_analysis_threaded(file1_path, file2_path, stream_type_filter, result_queue):
    """
    Runs the Raw vs. Extracted analysis on streams of a specific type in one or two files.
    """
    report = []

    def _process_file(filepath):
        """Helper function to run analysis on a single file."""
        file_report = []
        file_report.append(f"--- Analysis for: {os.path.basename(filepath)} ---")

        all_streams, err = get_stream_info(filepath)
        if err:
            file_report.append(f"  Error: {err}")
            return file_report

        streams_to_analyze = [s for s in all_streams if s.get('codec_type') == stream_type_filter]
        if not streams_to_analyze:
            file_report.append(f"No '{stream_type_filter}' streams found to analyze.")
            return file_report

        for stream in streams_to_analyze:
            stream_index = stream['index']
            codec_name = stream['codec_name']

            file_report.append(f"\nAnalyzing Stream #{stream_index} ({codec_name.upper()})")

            raw_hash, raw_err = get_raw_stream_hash_in_memory(filepath, stream_index, codec_name)
            if raw_err:
                file_report.append(f"  - Raw In-Memory Hash: ERROR - {raw_err}")
            else:
                file_report.append(f"  - Raw In-Memory Hash: {raw_hash}")

            extract_hash, extract_err = get_mkvextract_hash(filepath, stream_index)
            if extract_err:
                 file_report.append(f"  - Extracted File Hash: ERROR - {extract_err}")
            else:
                file_report.append(f"  - Extracted File Hash: {extract_hash}")

            if not raw_err and not extract_err:
                if raw_hash == extract_hash:
                    file_report.append("  - RESULT: Hashes match. No container delay is affecting extraction.")
                else:
                    file_report.append("  - RESULT: Hashes DO NOT match. A container delay is present.")
        return file_report

    if file1_path:
        report.extend(_process_file(file1_path))

    if file2_path:
        report.append("\n" + "="*40 + "\n") # Separator
        report.extend(_process_file(file2_path))

    result_queue.put(report)


# --- DearPyGui UI Setup ---

progress_queue = queue.Queue()
result_queue = queue.Queue()

def start_comparison(sender, app_data, user_data):
    """Callback for the main comparison buttons."""
    hash_function, method_name, stream_filter = user_data
    file1 = dpg.get_value("file1_input")
    file2 = dpg.get_value("file2_input")

    if not file1 or not file2:
        dpg.set_value("report_text", "Error: Please provide paths for both files for comparison.")
        return

    if stream_filter:
        stream_type_filter = dpg.get_value("individual_type_selector").lower()
        report_intro = f"Starting individual comparison of all '{stream_type_filter}' streams with method: {method_name}..."
    else:
        stream_type_filter = None
        report_intro = f"Starting comparison with '{method_name}' method..."

    dpg.set_value("report_text", report_intro)
    dpg.set_value("progress_bar", 0.0)
    dpg.configure_item("progress_bar", show=True)
    dpg.configure_item("full_comparison_group", show=False)
    dpg.configure_item("individual_type_group", show=False)
    dpg.configure_item("analysis_group", show=False)

    thread = threading.Thread(
        target=run_full_comparison_threaded,
        args=(hash_function, method_name, file1, file2, progress_queue, result_queue, stream_type_filter),
        daemon=True
    )
    thread.start()

def start_analysis(sender, app_data, user_data):
    """Callback for the analysis button."""
    file1 = dpg.get_value("file1_input")
    file2 = dpg.get_value("file2_input")

    if not file1 and not file2:
        dpg.set_value("report_text", "Error: Please provide a path for at least one file to analyze.")
        return

    stream_type = dpg.get_value("analysis_type_selector").lower()

    dpg.set_value("report_text", "Starting Raw vs. Extracted analysis...")
    dpg.configure_item("progress_bar", show=False)
    dpg.configure_item("full_comparison_group", show=False)
    dpg.configure_item("individual_type_group", show=False)
    dpg.configure_item("analysis_group", show=False)

    thread = threading.Thread(
        target=run_analysis_threaded,
        args=(file1, file2, stream_type, result_queue),
        daemon=True
    )
    thread.start()


def create_gui():
    """Creates the main DearPyGui window and its widgets."""
    dpg.create_context()

    with dpg.window(label="FFmpeg Media Comparator", tag="main_window", width=800, height=750):
        with dpg.group(horizontal=True):
            dpg.add_text("File 1 Path:")
            dpg.add_input_text(tag="file1_input", width=-1)

        with dpg.group(horizontal=True):
            dpg.add_text("File 2 Path:")
            dpg.add_input_text(tag="file2_input", width=-1)

        dpg.add_separator()
        dpg.add_text("Full File Comparison (All Streams)", color=(255, 255, 0))
        with dpg.group(horizontal=True, tag="full_comparison_group"):
            dpg.add_button(label="Compare (Fast, Stream Copy)", callback=start_comparison, user_data=(get_stream_hash_copied, "Stream Copy", False))
            dpg.add_button(label="Compare (Slow, Full Decode)", callback=start_comparison, user_data=(get_stream_hash_decoded, "Full Decode", False))
            dpg.add_button(label="Compare (Raw In-Memory Hash)", callback=start_comparison, user_data=(None, "Raw In-Memory Hash", False))

        dpg.add_separator()
        dpg.add_text("Individually Compare All Streams of a Specific Type", color=(255, 255, 0))
        with dpg.group(horizontal=True, tag="individual_type_group"):
            dpg.add_text("Stream Type:")
            dpg.add_combo(items=["Video", "Audio", "Subtitle"], tag="individual_type_selector", default_value="Audio", width=120)
            dpg.add_button(label="Run (Stream Copy)", callback=start_comparison, user_data=(get_stream_hash_copied, "Stream Copy", True))
            dpg.add_button(label="Run (Full Decode)", callback=start_comparison, user_data=(get_stream_hash_decoded, "Full Decode", True))
            dpg.add_button(label="Run (Raw In-Memory)", callback=start_comparison, user_data=(None, "Raw In-Memory Hash", True))

        dpg.add_separator()
        dpg.add_text("Analysis: Raw vs. Extracted Hash", color=(255, 255, 0))
        with dpg.group(horizontal=True, tag="analysis_group"):
            dpg.add_text("Stream Type:")
            dpg.add_combo(items=["Video", "Audio", "Subtitle"], tag="analysis_type_selector", default_value="Audio", width=120)
            dpg.add_button(label="Run Analysis on File 1 & 2", callback=start_analysis)
        dpg.add_text("This tool compares the raw stream data against the data from a standard extraction\nto prove if a container delay is present.", wrap=0)


        dpg.add_progress_bar(tag="progress_bar", default_value=0.0, width=-1, show=False)
        dpg.add_separator()

        dpg.add_text("Report:")
        dpg.add_input_text(tag="report_text", multiline=True, readonly=True, default_value="Awaiting comparison...", width=-1, height=-1)

    dpg.create_viewport(title='FFmpeg Media Comparator', width=800, height=750)
    dpg.setup_dearpygui()
    dpg.show_viewport()

def main_gui_loop():
    """The main event loop for the GUI."""
    ffmpeg_ok, error_msg = check_ffmpeg_installed()
    if not ffmpeg_ok:
        dpg.set_value("report_text", error_msg)
        dpg.configure_item("full_comparison_group", show=False)
        dpg.configure_item("individual_type_group", show=False)
        dpg.configure_item("analysis_group", show=False)

    while dpg.is_dearpygui_running():
        try:
            progress = progress_queue.get_nowait()
            dpg.set_value("progress_bar", progress)
        except queue.Empty:
            pass

        try:
            report_lines = result_queue.get_nowait()
            report_text = "\n".join(report_lines)
            dpg.set_value("report_text", report_text)
            dpg.configure_item("progress_bar", show=False)
            dpg.configure_item("full_comparison_group", show=True)
            dpg.configure_item("individual_type_group", show=True)
            dpg.configure_item("analysis_group", show=True)
        except queue.Empty:
            pass

        dpg.render_dearpygui_frame()

    dpg.destroy_context()

if __name__ == "__main__":
    create_gui()
    main_gui_loop()
