import os
import time
import json
import requests
import argparse
import csv
import random

# MalwareBazaar API key
MALWAREBAZAAR_API_KEY = "a7f5a8434edea24df954df7741636160c28"

# Rate limiting parameters (MalwareBazaar is more permissive than VirusTotal)
REQUESTS_PER_MINUTE = 10
SECONDS_BETWEEN_REQUESTS = 60 / REQUESTS_PER_MINUTE

# Paths
TRAINING_DIR = "./training_dataset"
CLUSTER_VERIFICATION_CSV = "./results/cluster_verification.csv"

def read_cluster_verification():
    """Read cluster verification results from CSV"""
    cluster_labels = {}
    cluster_info = {}
    
    with open(CLUSTER_VERIFICATION_CSV, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            cluster = int(row['cluster'])
            label = row['label']
            
            # Store cluster label
            if cluster not in cluster_labels:
                cluster_labels[cluster] = label
            
            # Extract common families and tags
            if cluster not in cluster_info:
                common_families = []
                common_tags = []
                
                if 'common_families' in row and row['common_families']:
                    for family_count in row['common_families'].split(';'):
                        if ':' in family_count:
                            # Split from the right to handle cases where family name contains colons
                            parts = family_count.rsplit(':', 1)
                            if len(parts) == 2:
                                family, count = parts
                                try:
                                    common_families.append((family, int(count)))
                                except ValueError:
                                    # Handle case where count is not an integer
                                    print(f"Warning: Invalid count format in {family_count}")
                
                if 'common_tags' in row and row['common_tags']:
                    for tag_count in row['common_tags'].split(';'):
                        if ':' in tag_count:
                            # Split from the right to handle cases where tag contains colons
                            parts = tag_count.rsplit(':', 1)
                            if len(parts) == 2:
                                tag, count = parts
                                try:
                                    common_tags.append((tag, int(count)))
                                except ValueError:
                                    # Handle case where count is not an integer
                                    print(f"Warning: Invalid count format in {tag_count}")
                
                # Get file type from the first file in the cluster
                file_type = "executable"
                if row['filename'].endswith('.exe'):
                    file_type = "exe"
                elif row['filename'].endswith('.elf'):
                    file_type = "elf"
                
                cluster_info[cluster] = {
                    'size': 0,  # Will be updated as we count files
                    'common_families': common_families,
                    'common_tags': common_tags,
                    'file_type': file_type,
                    'is_benign': label == "benign"
                }
            
            # Increment cluster size
            cluster_info[cluster]['size'] += 1
    
    return {
        'cluster_labels': cluster_labels,
        'cluster_info': cluster_info
    }

def query_malwarebazaar(query_type, query, limit=100):
    """Query MalwareBazaar for samples"""
    url = "https://mb-api.abuse.ch/api/v1/"
    
    data = {
        "query": query_type,
        "api_key": MALWAREBAZAAR_API_KEY,
        "limit": limit
    }
    
    if query_type == "get_taginfo":
        data["tag"] = query
    elif query_type == "get_siginfo":
        data["signature"] = query
    elif query_type == "get_file":
        data["sha256_hash"] = query
    elif query_type == "get_filetype":
        data["file_type"] = query
    
    try:
        response = requests.post(url, data=data)
        
        if response.status_code == 200:
            result = response.json()
            if result.get("query_status") == "ok":
                return {
                    "success": True,
                    "data": result.get("data", [])
                }
            else:
                return {
                    "success": False,
                    "error": result.get("query_status")
                }
        else:
            return {
                "success": False,
                "error": f"API error: {response.status_code}"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def download_sample_from_malwarebazaar(sha256_hash, destination_dir):
    """Download a specific sample from MalwareBazaar"""
    url = "https://mb-api.abuse.ch/api/v1/"
    
    data = {
        "query": "get_file",
        "sha256_hash": sha256_hash,
        "api_key": MALWAREBAZAAR_API_KEY
    }
    
    try:
        response = requests.post(url, data=data)
        
        if response.status_code == 200:
            # Create destination directory if it doesn't exist
            os.makedirs(destination_dir, exist_ok=True)
            
            # Save file
            file_path = os.path.join(destination_dir, f"{sha256_hash}")
            with open(file_path, 'wb') as f:
                f.write(response.content)
            
            # Check if the file is a ZIP file (MalwareBazaar returns samples as ZIP files)
            if response.content.startswith(b'PK'):
                print(f"    Downloaded sample is a ZIP file. Keeping as-is for analysis.")
                # Rename the file to indicate it's a ZIP
                zip_file_path = file_path + ".zip"
                os.rename(file_path, zip_file_path)
                file_path = zip_file_path
            
            return {
                "success": True,
                "file_path": file_path
            }
        else:
            return {
                "success": False,
                "error": f"API error: {response.status_code}"
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def download_training_dataset(samples_per_family=35, resume=False):
    """Download a balanced training dataset with rate limiting"""
    print("Downloading training dataset from MalwareBazaar with rate limiting...")
    
    # Create training dataset directory
    os.makedirs(TRAINING_DIR, exist_ok=True)
    
    # Get cluster verification results
    cluster_verification = read_cluster_verification()
    cluster_labels = cluster_verification['cluster_labels']
    cluster_info = cluster_verification['cluster_info']
    
    # Create progress tracking file
    progress_file = "download_mb_progress.json"
    progress = {}
    
    if resume and os.path.exists(progress_file):
        with open(progress_file, 'r') as f:
            progress = json.load(f)
        print(f"Resuming download from progress file: {progress}")
    
    # Download samples for each label
    for cluster, label in cluster_labels.items():
        # Skip benign samples (MalwareBazaar only has malware)
        if label == "benign":
            print(f"Skipping {label} (MalwareBazaar only has malware samples)")
            continue
        
        # Skip if already completed
        if label in progress and progress[label].get('completed', False):
            print(f"Skipping {label} (already completed)")
            continue
        
        print(f"Downloading samples for {label} (cluster {cluster})...")
        
        # Create directory for this label
        label_dir = os.path.join(TRAINING_DIR, label)
        os.makedirs(label_dir, exist_ok=True)
        
        # Initialize progress for this label if needed
        if label not in progress:
            progress[label] = {
                'search_completed': False,
                'file_hashes': [],
                'downloaded_hashes': [],
                'completed': False
            }
        
        # Construct search query based on cluster info
        info = cluster_info[cluster]
        
        # Search for samples if not already done
        if not progress[label]['search_completed']:
            # Try different query strategies
            file_hashes = []
            
            # Strategy 1: Search by malware family
            if not file_hashes and info.get('common_families'):
                for family_name, _ in info.get('common_families', [])[:3]:  # Try top 3 families
                    print(f"  Searching for samples with signature: {family_name}")
                    
                    # Clean up family name (remove special characters)
                    clean_family = ''.join(c for c in family_name if c.isalnum() or c.isspace()).strip()
                    if not clean_family:
                        continue
                    
                    search_result = query_malwarebazaar("get_siginfo", clean_family)
                    
                    # Wait to respect rate limit
                    print(f"  Waiting {SECONDS_BETWEEN_REQUESTS:.1f} seconds for rate limiting...")
                    time.sleep(SECONDS_BETWEEN_REQUESTS)
                    
                    if search_result.get("success", False):
                        data = search_result.get("data", [])
                        # Filter by file type if possible
                        filtered_data = [item for item in data if item.get("file_type", "").lower() == info.get("file_type", "").lower()]
                        if not filtered_data:
                            filtered_data = data  # Use all data if no matches for file type
                        
                        # Extract SHA256 hashes
                        new_hashes = [item.get("sha256_hash") for item in filtered_data if item.get("sha256_hash")]
                        file_hashes.extend(new_hashes[:samples_per_family])
                        
                        if len(file_hashes) >= samples_per_family:
                            break
            
            # Strategy 2: Search by file type
            if not file_hashes and info.get('file_type'):
                print(f"  Searching for samples with file type: {info.get('file_type')}")
                
                search_result = query_malwarebazaar("get_filetype", info.get('file_type'))
                
                # Wait to respect rate limit
                print(f"  Waiting {SECONDS_BETWEEN_REQUESTS:.1f} seconds for rate limiting...")
                time.sleep(SECONDS_BETWEEN_REQUESTS)
                
                if search_result.get("success", False):
                    data = search_result.get("data", [])
                    # Extract SHA256 hashes
                    new_hashes = [item.get("sha256_hash") for item in data if item.get("sha256_hash")]
                    file_hashes.extend(new_hashes[:samples_per_family])
            
            # Strategy 3: Search by tags
            if not file_hashes and info.get('common_tags'):
                for tag_name, _ in info.get('common_tags', [])[:3]:  # Try top 3 tags
                    print(f"  Searching for samples with tag: {tag_name}")
                    
                    search_result = query_malwarebazaar("get_taginfo", tag_name)
                    
                    # Wait to respect rate limit
                    print(f"  Waiting {SECONDS_BETWEEN_REQUESTS:.1f} seconds for rate limiting...")
                    time.sleep(SECONDS_BETWEEN_REQUESTS)
                    
                    if search_result.get("success", False):
                        data = search_result.get("data", [])
                        # Filter by file type if possible
                        filtered_data = [item for item in data if item.get("file_type", "").lower() == info.get("file_type", "").lower()]
                        if not filtered_data:
                            filtered_data = data  # Use all data if no matches for file type
                        
                        # Extract SHA256 hashes
                        new_hashes = [item.get("sha256_hash") for item in filtered_data if item.get("sha256_hash")]
                        file_hashes.extend(new_hashes[:samples_per_family])
                        
                        if len(file_hashes) >= samples_per_family:
                            break
            
            # Strategy 4: Get recent samples as a fallback
            if not file_hashes:
                print(f"  Searching for recent samples")
                
                search_result = query_malwarebazaar("get_recent", "")
                
                # Wait to respect rate limit
                print(f"  Waiting {SECONDS_BETWEEN_REQUESTS:.1f} seconds for rate limiting...")
                time.sleep(SECONDS_BETWEEN_REQUESTS)
                
                if search_result.get("success", False):
                    data = search_result.get("data", [])
                    # Filter by file type if possible
                    filtered_data = [item for item in data if item.get("file_type", "").lower() == info.get("file_type", "").lower()]
                    if not filtered_data:
                        filtered_data = data  # Use all data if no matches for file type
                    
                    # Extract SHA256 hashes
                    new_hashes = [item.get("sha256_hash") for item in filtered_data if item.get("sha256_hash")]
                    file_hashes.extend(new_hashes[:samples_per_family])
            
            # Limit to the requested number of samples
            file_hashes = file_hashes[:samples_per_family]
            
            print(f"  Found {len(file_hashes)} samples")
            
            # Update progress
            progress[label]['file_hashes'] = file_hashes
            progress[label]['search_completed'] = True
            
            # Save progress
            with open(progress_file, 'w') as f:
                json.dump(progress, f, indent=2)
        
        # Download each sample
        file_hashes = progress[label]['file_hashes']
        downloaded_hashes = progress[label]['downloaded_hashes']
        
        for i, file_hash in enumerate(file_hashes):
            # Skip if already downloaded
            if file_hash in downloaded_hashes:
                print(f"  Skipping sample {i+1}/{len(file_hashes)}: {file_hash} (already downloaded)")
                continue
            
            print(f"  Downloading sample {i+1}/{len(file_hashes)}: {file_hash}")
            
            download_result = download_sample_from_malwarebazaar(file_hash, label_dir)
            
            # Wait to respect rate limit
            print(f"  Waiting {SECONDS_BETWEEN_REQUESTS:.1f} seconds for rate limiting...")
            time.sleep(SECONDS_BETWEEN_REQUESTS)
            
            if not download_result.get("success", False):
                print(f"    Error downloading sample: {download_result.get('error', 'Unknown error')}")
            else:
                print(f"    Downloaded to {download_result.get('file_path')}")
                # Update progress
                downloaded_hashes.append(file_hash)
                progress[label]['downloaded_hashes'] = downloaded_hashes
                
                # Save progress after each download
                with open(progress_file, 'w') as f:
                    json.dump(progress, f, indent=2)
        
        # Mark as completed
        progress[label]['completed'] = True
        
        # Save progress
        with open(progress_file, 'w') as f:
            json.dump(progress, f, indent=2)
    
    print("Training dataset download complete.")
    return True

def generate_synthetic_benign_samples(samples_per_class=35):
    """Generate synthetic benign samples since MalwareBazaar doesn't have benign samples"""
    print("Generating synthetic benign samples...")
    
    # Create directory for benign samples
    benign_dir = os.path.join(TRAINING_DIR, "benign")
    os.makedirs(benign_dir, exist_ok=True)
    
    # Get list of existing benign files
    existing_files = [f for f in os.listdir(benign_dir) if os.path.isfile(os.path.join(benign_dir, f))]
    
    if not existing_files:
        print("  No existing benign files found. Cannot generate synthetic samples.")
        return False
    
    # Calculate how many synthetic samples to generate
    num_existing = len(existing_files)
    num_to_generate = max(0, samples_per_class - num_existing)
    
    if num_to_generate <= 0:
        print(f"  Already have {num_existing} benign samples. No need to generate more.")
        return True
    
    print(f"  Found {num_existing} existing benign files, generating {num_to_generate} synthetic samples")
    
    # For each synthetic sample to generate
    for i in range(num_to_generate):
        # Select a random existing file as a template
        template_file = random.choice(existing_files)
        template_path = os.path.join(benign_dir, template_file)
        
        # Read the file content
        with open(template_path, 'rb') as f:
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
        
        # Save the synthetic sample
        synthetic_file_name = f"synthetic_benign_{i}_{template_file}"
        synthetic_file_path = os.path.join(benign_dir, synthetic_file_name)
        
        with open(synthetic_file_path, 'wb') as f:
            f.write(synthetic_content)
        
        print(f"    Created synthetic benign sample: {synthetic_file_name}")
    
    print("Synthetic benign sample generation complete.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download training dataset from MalwareBazaar with rate limiting")
    parser.add_argument("--samples", type=int, default=35, help="Number of samples to download per family")
    parser.add_argument("--resume", action="store_true", help="Resume download from previous progress")
    parser.add_argument("--api-key", type=str, help="MalwareBazaar API key")
    parser.add_argument("--synthetic-benign", action="store_true", help="Generate synthetic benign samples")
    
    args = parser.parse_args()
    
    if args.api_key:
        MALWAREBAZAAR_API_KEY = args.api_key
    
    # Download malware samples
    download_training_dataset(samples_per_family=args.samples, resume=args.resume)
    
    # Generate synthetic benign samples if requested
    if args.synthetic_benign:
        generate_synthetic_benign_samples(samples_per_class=args.samples)
