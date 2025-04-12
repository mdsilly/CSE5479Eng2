import os
import csv
import shutil

# Paths
dataset_dir = "./dataset"
training_dir = "./training_dataset"
csv_file = "./results/cluster_verification.csv"

# Ensure training directories exist
for label in ["benign", "malicious1", "malicious2", "malicious3", "malicious4"]:
    os.makedirs(os.path.join(training_dir, label), exist_ok=True)

# Read the CSV file and copy files to appropriate directories
with open(csv_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        filename = row['filename']
        label = row['label']
        
        # Source and destination paths
        src_path = os.path.join(dataset_dir, filename)
        dst_path = os.path.join(training_dir, label, filename)
        
        # Copy the file
        if os.path.exists(src_path):
            print(f"Copying {filename} to {label} directory")
            shutil.copy2(src_path, dst_path)
        else:
            print(f"Warning: {src_path} does not exist")

print("Dataset organization complete!")
