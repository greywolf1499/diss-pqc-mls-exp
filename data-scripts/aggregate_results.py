"""
aggregate_results.py

This script is designed to process and aggregate raw benchmark data from
Criterion.rs for high-level cryptographic operations, such as those found in
MLS protocol. It navigates a directory of benchmark outputs, parsing JSON
files to extract performance metrics and metadata.

Usage:
    python aggregate_results.py -i <path_to_criterion_output> -o <master_csv_file> [-d <focused_output_dir>]
"""
import os
import json
import re
import pandas as pd
from tqdm import tqdm
import logging
import argparse
from pathlib import Path

# Configure basic logging to report informational messages and errors.
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Maps signature scheme names to their cryptographic family and security level.
# This provides essential context for analysis. The keys must exactly match the
# names used in the benchmark's 'value_str' field.
METADATA_MAP = {
    "ED25519": ("Classical", "N/A"),
    # NIST Level 1
    "MLDSA44": ("Lattice", "NIST Level 1"),
    "SPHINCS_SHA2_128F": ("Hash-Based", "NIST Level 1"),
    "SPHINCS_SHA2_128S": ("Hash-Based", "NIST Level 1"),
    "FALCON_512": ("Lattice", "NIST Level 1"),
    # NIST Level 3
    "MLDSA65": ("Lattice", "NIST Level 3"),
    "SPHINCS_SHA2_192F": ("Hash-Based", "NIST Level 3"),
    "SPHINCS_SHA2_192S": ("Hash-Based", "NIST Level 3"),
    # NIST Level 5
    "MLDSA87": ("Lattice", "NIST Level 5"),
    "SPHINCS_SHA2_256F": ("Hash-Based", "NIST Level 5"),
    "SPHINCS_SHA2_256S": ("Hash-Based", "NIST Level 5"),
    "FALCON_1024": ("Lattice", "NIST Level 5"),
}


def parse_group_id(group_id):
    """
    Parses a benchmark's group_id string to extract structured information.

    The group_id typically contains the operation name and the perspective from
    which it was measured (e.g., "Sender", "Receiver"). This function uses
    regular expressions and mapping to standardise these values.

    Args:
        group_id (str): The group_id string from the benchmark metadata.
                        Example: "3.1. Member Addition (Receiver - New Member)"

    Returns:
        tuple: A tuple containing the standardised category (str),
               operation name (str), and perspective (str).
    """
    try:
        # Remove the numeric prefix (e.g., "3.1. ") to get the base name.
        base_name = re.sub(r'^\d+(\.\d+)*\.\s+', '', group_id).strip()
        op_name = base_name
        perspective = "N/A"

        # Extract the perspective if it's present in parentheses.
        match = re.search(r'\s*\((.*)\)$', base_name)
        if match:
            op_name = base_name[:match.start()].strip()
            perspective_raw = match.group(1).strip()

            # Normalise different perspective strings to a standard set.
            perspective_map = {
                "Sender": "Sender",
                "Receiver - New Member": "Receiver (New)",
                "Receiver - Existing Member": "Receiver (Existing)",
                "Receiver": "Receiver",
                "Receive": "Receiver",
                "Send": "Sender",
                "Sender - SelfUpdate": "Sender",
                "Receiver - SelfUpdate": "Receiver",
            }
            perspective = perspective_map.get(perspective_raw, perspective_raw)

        # Standardise operation names for consistency.
        final_op_name = op_name
        if "Group Update" in op_name:
            final_op_name = "Self Update"

        # Categorise the operation based on its name.
        category = "Unknown"
        category_map = {
            "Key Package Creation": "Onboarding", "Group Creation": "Group Management",
            "Member Addition": "Group Management", "Self Update": "Group Management",
            "Member Removal": "Group Management", "Application Message": "Messaging",
        }
        for key, cat in category_map.items():
            if key in final_op_name:
                category = cat
                break

        # Ensure messaging operations have a consistent name.
        if category == "Messaging":
            final_op_name = "Application Message"

        return category, final_op_name, perspective
    except Exception as e:
        logging.warning(f"Could not parse group_id '{group_id}': {e}")
        return "Unknown", group_id, "Unknown"


def parse_value_str(value_str):
    """
    Parses the 'value_str' to extract group size and signature scheme.

    The 'value_str' can either be a simple signature scheme name or a
    compound string containing the group size and scheme.

    Args:
        value_str (str): The value string from benchmark metadata.
                         Examples: "FALCON_1024", "size=100, cs=MLDSA44"

    Returns:
        tuple: A tuple containing the group size (int) and signature scheme (str).
               Defaults to a group size of 1 if not specified.
    """
    pattern_full = re.compile(r'size=(\d+),\s*cs=([A-Z0-9_]+)')
    match_full = pattern_full.match(value_str)
    if match_full:
        return int(match_full.group(1)), match_full.group(2)
    # If the pattern doesn't match, assume it's just a signature scheme name.
    return 1, value_str


def main(root_dir, output_csv, output_dir):
    """
    Aggregates benchmark data into a master CSV and optional focused CSVs.

    Args:
        root_dir (str): The path to the root directory of the Criterion.rs output.
        output_csv (str): The path to save the master aggregated CSV file.
        output_dir (str or None): A directory path to save per-operation CSVs.
                                  If None, this step is skipped.
    """
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    all_records = []

    # Pre-scan for valid benchmark directories to enable a progress bar.
    benchmark_dirs = []
    for root, dirs, files in os.walk(root_dir):
        if 'new' in dirs:
            new_dir_path = os.path.join(root, 'new')
            if os.path.exists(os.path.join(new_dir_path, 'benchmark.json')) and \
               os.path.exists(os.path.join(new_dir_path, 'estimates.json')):
                benchmark_dirs.append(root)

    print(f"Found {len(benchmark_dirs)} benchmark result directories in '{os.path.abspath(root_dir)}'. Processing...")

    # Process each identified directory.
    for dir_path in tqdm(benchmark_dirs, desc="Aggregating Results"):
        try:
            benchmark_json_path = os.path.join(
                dir_path, 'new', 'benchmark.json')
            estimates_json_path = os.path.join(
                dir_path, 'new', 'estimates.json')

            with open(benchmark_json_path, 'r') as f:
                metadata = json.load(f)
            with open(estimates_json_path, 'r') as f:
                estimates = json.load(f)

            # Parse metadata to extract and enrich data fields.
            group_id = metadata.get('group_id', 'Unknown')
            value_str = metadata.get('value_str', 'Unknown')
            category, name, perspective = parse_group_id(group_id)
            group_size, sig_scheme = parse_value_str(value_str)
            family, security_level = METADATA_MAP.get(
                sig_scheme, ("Unknown", "Unknown"))
            mean = estimates.get('mean', {})
            median = estimates.get('median', {})

            # Compile the processed data into a dictionary.
            record = {
                'Operation_Category': category, 'Operation_Name': name, 'Perspective': perspective,
                'Signature_Scheme': sig_scheme, 'Algorithm_Family': family, 'Security_Level': security_level,
                'Group_Size': group_size, 'Mean_Time_ns': mean.get('point_estimate'),
                'Mean_Lower_Bound_ns': mean.get('confidence_interval', {}).get('lower_bound'),
                'Mean_Upper_Bound_ns': mean.get('confidence_interval', {}).get('upper_bound'),
                'Median_Time_ns': median.get('point_estimate'),
                'Median_Lower_Bound_ns': median.get('confidence_interval', {}).get('lower_bound'),
                'Median_Upper_Bound_ns': median.get('confidence_interval', {}).get('upper_bound'),
                'Source_Path': os.path.relpath(estimates_json_path, root_dir)
            }
            all_records.append(record)
        except Exception as e:
            logging.error(f"Failed to process directory '{dir_path}': {e}")

    if not all_records:
        print(
            f"No benchmark records were found. Please check the directory '{root_dir}'.")
        return

    df = pd.DataFrame(all_records)
    # Define a consistent column order for the output CSV.
    column_order = [
        'Operation_Category', 'Operation_Name', 'Perspective', 'Signature_Scheme',
        'Algorithm_Family', 'Security_Level', 'Group_Size', 'Mean_Time_ns',
        'Mean_Lower_Bound_ns', 'Mean_Upper_Bound_ns', 'Median_Time_ns',
        'Median_Lower_Bound_ns', 'Median_Upper_Bound_ns', 'Source_Path'
    ]
    df = df[column_order]

    # Save the master dataset.
    df.to_csv(output_csv, index=False)

    print("\n" + "="*50)
    print("      Master Data Aggregation Complete!")
    print("="*50)
    print(f"Successfully processed {len(df)} benchmark records.")
    print(f"Master dataset saved to: '{os.path.abspath(output_csv)}'")

    # If an output directory is specified, create focused datasets.
    if output_dir:
        print(
            f"\nSaving focused datasets to '{os.path.abspath(output_dir)}'...")

        # Group data by category and operation name to create separate files.
        for (category, op_name), group_df in df.groupby(['Operation_Category', 'Operation_Name']):

            # Sanitise names to be filesystem-friendly.
            cat_path = category.lower().replace(' ', '_')
            op_path = op_name.lower().replace(' ', '_')

            # Create a subdirectory for the category.
            category_dir = Path(output_dir) / cat_path
            category_dir.mkdir(parents=True, exist_ok=True)

            # Define and save the focused CSV file.
            file_path = category_dir / f"{op_path}.csv"
            group_df.to_csv(file_path, index=False)

        print("Focused datasets saved successfully.")

    print("\nFirst 5 rows of the master dataset:")
    print(df.head().to_string())
    print("\nReady for analysis!")


if __name__ == '__main__':
    # Set up command-line argument parsing.
    parser = argparse.ArgumentParser(
        description="Aggregate Criterion.rs benchmark data into a master CSV and focused datasets.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-i', '--input-dir', default='../pqc-openmls/target/criterion',
        help="Path to the root directory containing the benchmark results."
    )
    parser.add_argument(
        '-o', '--output-file', default='./results/master_benchmark_results.csv',
        help="Path to save the main aggregated CSV file."
    )
    parser.add_argument(
        '-d', '--output-dir', default='./results/focused_ops',
        help="Path to a directory to save focused, per-operation CSV files. If not provided, this step is skipped."
    )

    args = parser.parse_args()
    main(root_dir=args.input_dir, output_csv=args.output_file,
         output_dir=args.output_dir)
