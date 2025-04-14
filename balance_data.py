#!/usr/bin/env python3
"""
Balance Training Data

This script ensures balanced training data by:
1. Analyzing the distribution of samples across different classes
2. Downsampling overrepresented classes
3. Generating synthetic samples for underrepresented classes if needed

Usage:
    python balance_data.py [--target_samples N] [--no-downsample] [--no-synthetic]
"""

import os
import sys
import argparse
import random
import shutil
import numpy as np
from collections import Counter
import hashlib
import time

# Add the parent directory to the path so we can import from script.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import functions from script.py
try:
    from script import generate_synthetic_samples
except ImportError:
    print("Warning: Could not import generate_synthetic_samples from script.py")
    generate_synthetic_samples = None

# Directories
TRAINING_DIR = "./training_data"
BALANCED_DIR = "./balanced_training_data"
TEMP_DIR = "./temp_synthetic_samples"

def analyze_distribution(training_dir=TRAINING_DIR):
    """Analyze the distribution of samples across different classes"""
    print("Analyzing distribution of samples across classes...")
    
    class_counts = {}
    
    # Count benign samples
    benign_dir = os.path.join(training_dir, "benign")
    if os.path.exists(benign_dir) and os.path.isdir(benign_dir):
        benign_files = [f for f in os.listdir(benign_dir) if os.path.isfile(os.path.join(benign_dir, f))]
        class_counts["benign"] = len(benign_files)
    
    # Count malicious samples by family
    malicious_dir = os.path.join(training_dir, "malicious")
    if os.path.exists(malicious_dir) and os.path.isdir(malicious_dir):
        for family in os.listdir(malicious_dir):
            family_dir = os.path.join(malicious_dir, family)
            if os.path.isdir(family_dir) and not family.endswith("_progress.json"):
                # Count files in the main directory
                family_files = [f for f in os.listdir(family_dir) if os.path.isfile(os.path.join(family_dir, f))]
                count = len(family_files)
                
                # Check for synthetic subdirectory
                synthetic_dir = os.path.join(family_dir, "synthetic")
                if os.path.exists(synthetic_dir) and os.path.isdir(synthetic_dir):
                    # Count files in the synthetic directory
                    synthetic_files = [f for f in os.listdir(synthetic_dir) if os.path.isfile(os.path.join(synthetic_dir, f))]
                    count += len(synthetic_files)
                
                class_counts[family] = count
    
    # Print distribution
    print("\nCurrent distribution:")
    total_samples = sum(class_counts.values())
    for class_name, count in sorted(class_counts.items()):
        print(f"  {class_name}: {count} samples ({count/total_samples*100:.2f}%)")
    
    return class_counts

def downsample_class(source_dir, target_dir, target_samples):
    """Downsample a class by randomly selecting a subset of samples"""
    print(f"Downsampling {source_dir} to {target_samples} samples...")
    
    # Create target directory if it doesn't exist
    os.makedirs(target_dir, exist_ok=True)
    
    # Get list of files
    files = [f for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]
    
    # If we already have the right number of samples, just copy them all
    if len(files) <= target_samples:
        for file in files:
            shutil.copy2(os.path.join(source_dir, file), os.path.join(target_dir, file))
        return len(files)
    
    # Randomly select a subset of files
    selected_files = random.sample(files, target_samples)
    
    # Copy selected files to target directory
    for file in selected_files:
        shutil.copy2(os.path.join(source_dir, file), os.path.join(target_dir, file))
    
    return len(selected_files)

def generate_synthetic_sample(template_file, output_dir, index):
    """Generate a synthetic sample based on a template file"""
    # Read the file content
    with open(template_file, 'rb') as f:
        content = bytearray(f.read())
    
    # Create a copy of the content
    synthetic_content = bytearray(content)
    
    # Apply random modifications
    # 1. Modify a small percentage of bytes (1-5%)
    num_bytes_to_modify = max(1, int(len(synthetic_content) * (0.01 + 0.04 * random.random())))
    for _ in range(num_bytes_to_modify):
        idx = random.randint(0, len(synthetic_content) - 1)
        synthetic_content[idx] = random.randint(0, 255)
    
    # 2. Insert a small number of random bytes (0-2%)
    if len(synthetic_content) > 100:  # Only if file is large enough
        num_bytes_to_insert = int(len(synthetic_content) * (0.02 * random.random()))
        for _ in range(num_bytes_to_insert):
            idx = random.randint(0, len(synthetic_content) - 1)
            synthetic_content.insert(idx, random.randint(0, 255))
    
    # 3. Remove a small number of bytes (0-2%)
    if len(synthetic_content) > 100:  # Only if file is large enough
        num_bytes_to_remove = int(len(synthetic_content) * (0.02 * random.random()))
        for _ in range(num_bytes_to_remove):
            if len(synthetic_content) > 1:  # Ensure we don't remove all bytes
                idx = random.randint(0, len(synthetic_content) - 1)
                del synthetic_content[idx]
    
    # Generate a unique hash for the synthetic sample
    hash_obj = hashlib.sha256()
    hash_obj.update(synthetic_content)
    synthetic_hash = hash_obj.hexdigest()
    
    # Get file extension from template
    _, ext = os.path.splitext(template_file)
    if not ext:
        # If no extension, try to determine from content
        if synthetic_content.startswith(b'MZ'):
            ext = '.exe'
        elif synthetic_content.startswith(b'\x7fELF'):
            ext = '.elf'
        else:
            ext = '.bin'
    
    # Save the synthetic sample
    synthetic_file_path = os.path.join(output_dir, f"synthetic_{synthetic_hash[:8]}_{index}{ext}")
    
    with open(synthetic_file_path, 'wb') as f:
        f.write(synthetic_content)
    
    return synthetic_file_path

def upsample_class(source_dir, target_dir, target_samples):
    """Upsample a class by generating synthetic samples"""
    print(f"Upsampling {source_dir} to {target_samples} samples...")
    
    # Create target directory if it doesn't exist
    os.makedirs(target_dir, exist_ok=True)
    
    # Get list of files
    files = [f for f in os.listdir(source_dir) if os.path.isfile(os.path.join(source_dir, f))]
    
    # If we already have more than the target number of samples, downsample instead
    if len(files) >= target_samples:
        return downsample_class(source_dir, target_dir, target_samples)
    
    # First, copy all existing files
    for file in files:
        shutil.copy2(os.path.join(source_dir, file), os.path.join(target_dir, file))
    
    # Calculate how many synthetic samples to generate
    num_synthetic = target_samples - len(files)
    print(f"  Generating {num_synthetic} synthetic samples...")
    
    # Create temporary directory for synthetic samples
    os.makedirs(TEMP_DIR, exist_ok=True)
    
    # Generate synthetic samples
    synthetic_count = 0
    template_files = [os.path.join(source_dir, f) for f in files]
    
    while synthetic_count < num_synthetic:
        # Select a random template file
        template_file = random.choice(template_files)
        
        # Generate a synthetic sample
        synthetic_file = generate_synthetic_sample(template_file, TEMP_DIR, synthetic_count)
        
        # Copy to target directory
        shutil.copy2(synthetic_file, target_dir)
        
        synthetic_count += 1
        if synthetic_count % 10 == 0:
            print(f"  Generated {synthetic_count}/{num_synthetic} synthetic samples...")
    
    # Clean up temporary directory
    shutil.rmtree(TEMP_DIR)
    
    return len(files) + synthetic_count

def balance_training_data(target_samples=None, allow_downsample=True, allow_synthetic=True):
    """Balance training data by downsampling or generating synthetic samples"""
    print("Balancing training data...")
    
    # Analyze current distribution
    class_counts = analyze_distribution()
    
    if not class_counts:
        print("Error: No classes found in training directory.")
        return False
    
    # Determine target number of samples per class if not specified
    if target_samples is None:
        if allow_downsample:
            # If downsampling is allowed, use the minimum class size
            target_samples = min(class_counts.values())
        else:
            # If downsampling is not allowed, use the maximum class size
            target_samples = max(class_counts.values())
    
    print(f"\nTarget samples per class: {target_samples}")
    
    # Create balanced directory if it doesn't exist
    os.makedirs(BALANCED_DIR, exist_ok=True)
    
    # Create benign directory
    balanced_benign_dir = os.path.join(BALANCED_DIR, "benign")
    os.makedirs(balanced_benign_dir, exist_ok=True)
    
    # Create malicious directory
    balanced_malicious_dir = os.path.join(BALANCED_DIR, "malicious")
    os.makedirs(balanced_malicious_dir, exist_ok=True)
    
    # Balance benign class
    benign_dir = os.path.join(TRAINING_DIR, "benign")
    if os.path.exists(benign_dir) and os.path.isdir(benign_dir):
        if class_counts.get("benign", 0) > target_samples and allow_downsample:
            # Downsample benign class
            downsample_class(benign_dir, balanced_benign_dir, target_samples)
        elif class_counts.get("benign", 0) < target_samples and allow_synthetic:
            # Upsample benign class
            upsample_class(benign_dir, balanced_benign_dir, target_samples)
        else:
            # Just copy all files
            for file in os.listdir(benign_dir):
                file_path = os.path.join(benign_dir, file)
                if os.path.isfile(file_path):
                    shutil.copy2(file_path, os.path.join(balanced_benign_dir, file))
    
    # Balance malicious classes
    malicious_dir = os.path.join(TRAINING_DIR, "malicious")
    if os.path.exists(malicious_dir) and os.path.isdir(malicious_dir):
        for family in os.listdir(malicious_dir):
            family_dir = os.path.join(malicious_dir, family)
            if os.path.isdir(family_dir) and not family.endswith("_progress.json"):
                balanced_family_dir = os.path.join(balanced_malicious_dir, family)
                os.makedirs(balanced_family_dir, exist_ok=True)
                
                if class_counts.get(family, 0) > target_samples and allow_downsample:
                    # Downsample malicious class
                    downsample_class(family_dir, balanced_family_dir, target_samples)
                elif class_counts.get(family, 0) < target_samples and allow_synthetic:
                    # Upsample malicious class
                    upsample_class(family_dir, balanced_family_dir, target_samples)
                else:
                    # Just copy all files
                    for file in os.listdir(family_dir):
                        file_path = os.path.join(family_dir, file)
                        if os.path.isfile(file_path):
                            shutil.copy2(file_path, os.path.join(balanced_family_dir, file))
    
    # Verify final class distribution
    print("\nVerifying balanced distribution:")
    balanced_class_counts = {}
    
    # Count benign samples
    if os.path.exists(balanced_benign_dir) and os.path.isdir(balanced_benign_dir):
        benign_files = [f for f in os.listdir(balanced_benign_dir) if os.path.isfile(os.path.join(balanced_benign_dir, f))]
        balanced_class_counts["benign"] = len(benign_files)
    
    # Count malicious samples by family
    if os.path.exists(balanced_malicious_dir) and os.path.isdir(balanced_malicious_dir):
        for family in os.listdir(balanced_malicious_dir):
            family_dir = os.path.join(balanced_malicious_dir, family)
            if os.path.isdir(family_dir):
                family_files = [f for f in os.listdir(family_dir) if os.path.isfile(os.path.join(family_dir, f))]
                balanced_class_counts[family] = len(family_files)
    
    # Print balanced distribution
    total_balanced_samples = sum(balanced_class_counts.values())
    for class_name, count in sorted(balanced_class_counts.items()):
        print(f"  {class_name}: {count} samples ({count/total_balanced_samples*100:.2f}%)")
    
    print("\nBalancing complete. Balanced data is available in:", BALANCED_DIR)
    return True

def main():
    """Main function with command-line argument parsing"""
    parser = argparse.ArgumentParser(description="Balance training data by downsampling or generating synthetic samples")
    parser.add_argument("--target-samples", type=int, help="Target number of samples per class")
    parser.add_argument("--no-downsample", action="store_true", help="Disable downsampling of overrepresented classes")
    parser.add_argument("--no-synthetic", action="store_true", help="Disable generation of synthetic samples")
    
    args = parser.parse_args()
    
    balance_training_data(
        target_samples=args.target_samples,
        allow_downsample=not args.no_downsample,
        allow_synthetic=not args.no_synthetic
    )

if __name__ == "__main__":
    main()
