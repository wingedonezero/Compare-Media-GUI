Compare Media GUI

A powerful Python and DearPyGui-based utility for deep-analyzing and comparing video and audio files. This tool leverages FFmpeg and MKVToolNix to go beyond simple file hashes, allowing you to verify stream integrity, diagnose container-level issues, and confirm if two media streams are truly bit-for-bit identical.
Features

    Multiple Comparison Modes: Choose from fast, container-level checks to deep, raw-data analysis.

    Stream Filtering: Compare all streams in a file or focus only on specific types (Video, Audio, Subtitle).

    Container Delay Analysis: A dedicated tool to definitively prove if a container-level delay is altering a stream during standard extraction.

    Graphical User Interface: An easy-to-use GUI built with DearPyGui.

    Cross-Platform: Runs on any system with the required dependencies (Windows, macOS, Linux).

Requirements

Before running the application, you must have the following software installed and accessible in your system's PATH:

    Python 3: The programming language the script is written in.

    DearPyGui: The GUI library. Install it with pip:

    pip install dearpygui

    FFmpeg & FFprobe: The core multimedia toolkit for hashing and analysis.

    MKVToolNix: Specifically, the mkvextract command-line tool is required for the "Raw vs. Extracted Hash" analysis feature.

Usage

    Clone or download the repository.

    Ensure all requirements are installed.

    Run the script from your terminal:

    python compare_media_gui.py

    Paste the full paths to the two files you want to compare into the "File 1 Path" and "File 2 Path" input boxes.

    Select the desired comparison or analysis mode and click the corresponding button.

Comparison Modes Explained

The application offers several methods to compare files, each with distinct benefits and downfalls. Understanding the difference is key to getting the results you need.
Compare (Fast, Stream Copy)

    What it does: This mode performs a standard "stream copy" and hashes the resulting data. It's equivalent to hashing a stream exactly as it exists inside the container, including all its timing and metadata.

    Benefits:

        Extremely Fast: It's the quickest comparison method as it doesn't decode or re-encode any data.

        Good for Identical Files: Perfect for verifying if two files are exact, unmodified copies of each other.

    Downfalls:

        Too Sensitive: This mode is not suitable for checking if the underlying content is the same. Any tiny difference in container metadata, timestamps, or a delay added by mkvmerge will result in a different hash, even if the audio and video are bit-for-bit identical.

Compare (Slow, Full Decode)

    What it does: This mode decodes each stream to its raw, uncompressed form (e.g., raw video frames or PCM audio) and then hashes that decoded data. It's like asking, "What does this stream look and sound like after all container instructions are applied?"

    Benefits:

        Accurate Content Check: It ignores minor container differences and focuses on the final, playable content.

        Detects Re-encoding: It will correctly identify if a file has been re-encoded, even if it was saved with the same settings.

    Downfalls:

        Very Slow: Decoding entire video and audio streams is computationally expensive and can take a long time for large files.

        Affected by Delays: As we discovered, this mode is not immune to container delays. If a negative delay causes the beginning of a stream to be trimmed, the decoded output will be different, and the hashes will not match.

Compare (Raw In-Memory Hash)

    What it does: This is the most powerful and "pure" comparison method. It uses FFmpeg's "dumb" demuxer to extract the raw, unaltered stream data directly from the container, completely ignoring all container-level timing instructions, delays, or metadata. It then hashes this raw data.

    Benefits:

        The "Ground Truth": This is the definitive method for proving if the underlying stream data is bit-for-bit identical between two files, regardless of any container-level modifications.

        Unaffected by Delays: It will correctly report a match between an original file and a version that has had a delay applied, as long as the underlying data is the same.

    Downfalls:

        Slower than Stream Copy: It's faster than a full decode but slower than a simple stream copy.

        Requires Codec Support: It relies on a specific list of raw stream formats. While it supports all common types, it may fail on very obscure or new codecs.

Analysis Tool Explained
Analysis: Raw vs. Extracted Hash

This is not a comparison tool, but a diagnostic tool. Its purpose is to prove whether a container-level delay is present in a file.

    What it does: For each stream in a file, it performs two separate hashes:

        Raw In-Memory Hash: The "ground truth" hash of the unaltered stream data.

        Extracted File Hash: It uses mkvextract to save the stream to a temporary file and then hashes that file. mkvextract is a "smart" tool that reads and applies container delays.

    How to Interpret the Results:

        If the hashes MATCH: This proves that the file has no container delay affecting that stream. The raw data is identical to what a standard tool would extract.

        If the hashes DO NOT MATCH: This is definitive proof that the file has a container delay. The mkvextract tool has trimmed or padded the stream based on the container's instructions, creating a physically different file.

This tool is essential for understanding why two files that should be identical might be failing other comparison checks.
