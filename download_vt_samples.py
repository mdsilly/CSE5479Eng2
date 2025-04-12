import os
import time
import json
import requests
import argparse
import csv

# VirusTotal API key - replace with your own
VIRUSTOTAL_API_KEY = "4bec2a8a6760888abfa7028993553434eabcbd6618ba9042142e962db9be1905"

# Rate limiting parameters
REQUESTS_PER_MINUTE = 4
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
                    file_type = "peexe"
                elif row['filename'].endswith('.elf'):
                    file_type = "elf"
                
                cluster_info[cluster] = {
                    'size': 0,  # Will be updated as we count files
                    'common_families': common_families,
                    'common_tags': common_tags,
                    'common_file_type': file_type,
                    'is_benign': label == "benign"
                }
            
            # Increment cluster size
            cluster_info[cluster]['size'] += 1
    
    return {
        'cluster_labels': cluster_labels,
        'cluster_info': cluster_info
    }

def search_virustotal_for_samples(query, limit=10):
    """Search VirusTotal for samples matching a query"""
    try:
        url = "https://www.virustotal.com/api/v3/intelligence/search"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        params = {
            "query": query,
            "limit": limit
        }
        
        response = requests.get(url, headers=headers, params=params)
        
        if response.status_code == 200:
            result = response.json()
            items = result.get("data", [])
            
            # Extract file hashes
            file_hashes = []
            for item in items:
                file_hash = item.get("id")
                if file_hash:
                    file_hashes.append(file_hash)
            
            return {
                "success": True,
                "file_hashes": file_hashes,
                "count": len(file_hashes)
            }
        else:
            return {"error": f"API error: {response.status_code}", "details": response.text}
    
    except Exception as e:
        return {"error": str(e)}

def download_sample_from_virustotal(file_hash, destination_dir):
    """Download a specific sample from VirusTotal"""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/download"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(url, headers=headers, stream=True)
        
        if response.status_code == 200:
            # Create destination directory if it doesn't exist
            os.makedirs(destination_dir, exist_ok=True)
            
            # Save file
            file_path = os.path.join(destination_dir, f"{file_hash}")
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return {
                "success": True,
                "file_path": file_path
            }
        else:
            return {"error": f"API error: {response.status_code}", "details": response.text}
    
    except Exception as e:
        return {"error": str(e)}

def download_training_dataset(samples_per_family=35, resume=False):
    """Download a balanced training dataset with rate limiting"""
    print("Downloading training dataset from VirusTotal with rate limiting...")
    
    # Create training dataset directory
    os.makedirs(TRAINING_DIR, exist_ok=True)
    
    # Get cluster verification results
    cluster_verification = read_cluster_verification()
    cluster_labels = cluster_verification['cluster_labels']
    cluster_info = cluster_verification['cluster_info']
    
    # Create progress tracking file
    progress_file = "download_progress.json"
    progress = {}
    
    if resume and os.path.exists(progress_file):
        with open(progress_file, 'r') as f:
            progress = json.load(f)
        print(f"Resuming download from progress file: {progress}")
    
    # Download samples for each label
    for cluster, label in cluster_labels.items():
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
            if label == "benign":
                # For benign samples, search for clean files
                query = "tag:clean type:executable"
            else:
                # For malicious samples, use the most common family
                common_families = info.get('common_families', [])
                if common_families:
                    family_name = common_families[0][0]
                    query = f"tag:malicious {family_name} type:{info['common_file_type']}"
                else:
                    # Fallback if no common families found
                    query = f"tag:malicious type:{info['common_file_type']}"
            
            print(f"  Search query: {query}")
            
            # Search for samples
            search_result = search_virustotal_for_samples(query, limit=samples_per_family)
            
            # Wait to respect rate limit
            print(f"  Waiting {SECONDS_BETWEEN_REQUESTS:.1f} seconds for rate limiting...")
            time.sleep(SECONDS_BETWEEN_REQUESTS)
            
            if 'error' in search_result:
                print(f"  Error searching for samples: {search_result['error']}")
                # Save progress
                with open(progress_file, 'w') as f:
                    json.dump(progress, f, indent=2)
                continue
            
            file_hashes = search_result.get('file_hashes', [])
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
            
            download_result = download_sample_from_virustotal(file_hash, label_dir)
            
            # Wait to respect rate limit
            print(f"  Waiting {SECONDS_BETWEEN_REQUESTS:.1f} seconds for rate limiting...")
            time.sleep(SECONDS_BETWEEN_REQUESTS)
            
            if 'error' in download_result:
                print(f"    Error downloading sample: {download_result['error']}")
            else:
                print(f"    Downloaded to {download_result['file_path']}")
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download training dataset from VirusTotal with rate limiting")
    parser.add_argument("--samples", type=int, default=35, help="Number of samples to download per family")
    parser.add_argument("--resume", action="store_true", help="Resume download from previous progress")
    parser.add_argument("--api-key", type=str, help="VirusTotal API key")
    
    args = parser.parse_args()
    
    if args.api_key:
        VIRUSTOTAL_API_KEY = args.api_key
    
    download_training_dataset(samples_per_family=args.samples, resume=args.resume)
