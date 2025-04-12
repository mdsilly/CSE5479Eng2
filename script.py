import os
import numpy as np
import pandas as pd
import argparse
import subprocess
import time
from collections import Counter
import hashlib
import math
from PIL import Image
from sklearn.preprocessing import normalize
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics import silhouette_score

# Check if tensorflow/keras is installed, if not, warn the user
import tensorflow as tf
from tensorflow import keras
from keras import layers
TF_AVAILABLE = True
# Check if ember is installed, if not, warn the user
try:
    import ember
    EMBER_AVAILABLE = True
except ImportError:
    print("Warning: EMBER not installed. PE feature extraction will be limited.")
    print("Install with: pip install ember")
    EMBER_AVAILABLE = False

# Check if pefile is installed, if not, warn the user
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    print("Warning: pefile not installed. PE header analysis will be limited.")
    print("Install with: pip install pefile")
    PEFILE_AVAILABLE = False

import elftools
from elftools.elf.elffile import ELFFile
import requests
# Directories
DIR = "./dataset"
IMG_TRAIN_DIR = "./images/train"
IMG_VAL_DIR = "./images/validate"
IMG_SIZE = 128
BATCH_SIZE = 16

# Mapping labels
LABELS = {"benign": 0, "malicious1": 1, "malicious2": 2, "malicious3": 3, "malicious4": 4}
INV_LABELS = {v: k for k, v in LABELS.items()}

# VirusTotal API key - replace with your own if available
VIRUSTOTAL_API_KEY = "4bec2a8a6760888abfa7028993553434eabcbd6618ba9042142e962db9be1905"

#######################
# UTILITY FUNCTIONS
#######################

def init_directories():
    """Create necessary directories if they don't exist"""
    os.makedirs(IMG_TRAIN_DIR, exist_ok=True)
    os.makedirs(IMG_VAL_DIR, exist_ok=True)
    os.makedirs("./results", exist_ok=True)
    
    # Create label directories for training images
    for label in LABELS.keys():
        os.makedirs(os.path.join(IMG_TRAIN_DIR, label), exist_ok=True)

def get_file_type(file_path):
    """Determine if a file is PE, ELF, or unknown"""
    with open(file_path, 'rb') as f:
        magic = f.read(4)
    
    # Check for PE signature (MZ header)
    if magic.startswith(b'MZ'):
        return "PE"
    # Check for ELF signature
    elif magic.startswith(b'\x7fELF'):
        return "ELF"
    else:
        return "UNKNOWN"

def calculate_entropy(data):
    """Calculate Shannon entropy of data"""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    
    return entropy

def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

#######################
# FEATURE EXTRACTION
#######################

def create_greyscale_image(file_path, label=None, file_name=None, train=True):
    """Convert file content to a 128x128 grayscale image using Pillow"""
    # Check if the file is a ZIP file
    # is_zip = file_path.endswith('.zip')
    
    # if is_zip:
        # For ZIP files, use the first 16KB of the ZIP file itself
    """ ------- Convert file content to a 128x128 grayscale image using Pillow  ------ """
    with open(file_path, 'rb') as f:
        byte_data = np.frombuffer(f.read(), dtype=np.uint8)

    if len(byte_data) == 0:
        byte_data = np.zeros(IMG_SIZE * IMG_SIZE, dtype=np.uint8) 

    padded_data = np.zeros(IMG_SIZE * IMG_SIZE, dtype=np.uint8)
    padded_data[:min(len(byte_data), IMG_SIZE * IMG_SIZE)] = byte_data[:IMG_SIZE * IMG_SIZE]
    img_array = padded_data.reshape((IMG_SIZE, IMG_SIZE))
    img = Image.fromarray(img_array, mode='L')
    
    # Save the image if needed
    if file_name:
        if train and label:
            img.save(os.path.join(IMG_TRAIN_DIR, label, file_name[:9] + '.jpg'))
        elif not train:
            img.save(os.path.join(IMG_VAL_DIR, file_name[:9] + '.jpg'))
    
    return np.array(img)

def extract_pe_features(file_path):
    """Extract features from PE files"""
    features = {}
    
    # Basic file info
    file_size = os.path.getsize(file_path)
    features['file_size'] = file_size
    
    # Calculate entropy of the whole file
    with open(file_path, 'rb') as f:
        data = f.read()
        features['entropy'] = calculate_entropy(data)
    
    # Use pefile for detailed PE analysis if available
    if PEFILE_AVAILABLE:
        try:
            pe = pefile.PE(file_path)
            
            # Header information
            features['number_of_sections'] = len(pe.sections)
            features['timestamp'] = pe.FILE_HEADER.TimeDateStamp
            
            # Section information
            section_entropies = []
            section_sizes = []
            executable_sections = 0
            
            for section in pe.sections:
                section_entropies.append(calculate_entropy(section.get_data()))
                section_sizes.append(section.SizeOfRawData)
                if section.Characteristics & 0x20000000:  # Check if section is executable
                    executable_sections += 1
            
            features['avg_section_entropy'] = np.mean(section_entropies) if section_entropies else 0
            features['max_section_entropy'] = max(section_entropies) if section_entropies else 0
            features['avg_section_size'] = np.mean(section_sizes) if section_sizes else 0
            features['executable_sections'] = executable_sections
            
            # Import information
            try:
                features['number_of_imports'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                import_dlls = [imp.dll.decode('utf-8', 'ignore').lower() for imp in pe.DIRECTORY_ENTRY_IMPORT]
                features['has_wininet'] = 1 if any('wininet' in dll for dll in import_dlls) else 0
                features['has_crypt'] = 1 if any('crypt' in dll for dll in import_dlls) else 0
            except AttributeError:
                features['number_of_imports'] = 0
                features['has_wininet'] = 0
                features['has_crypt'] = 0
            
            # Export information
            try:
                features['number_of_exports'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            except AttributeError:
                features['number_of_exports'] = 0
                
        except Exception as e:
            print(f"Error analyzing PE file {file_path}: {e}")
            # Set default values for all PE-specific features
            features['number_of_sections'] = 0
            features['timestamp'] = 0
            features['avg_section_entropy'] = 0
            features['max_section_entropy'] = 0
            features['avg_section_size'] = 0
            features['executable_sections'] = 0
            features['number_of_imports'] = 0
            features['has_wininet'] = 0
            features['has_crypt'] = 0
            features['number_of_exports'] = 0
    
    # Use EMBER for advanced PE features if available
    if EMBER_AVAILABLE:
        try:
            feature_version = 2
            extractor = ember.PEFeatureExtractor(feature_version)
            with open(file_path, 'rb') as f:
                file_data = f.read()
            ember_features = np.array(extractor.feature_vector(file_data), dtype=np.float32)
            # Add EMBER features to our feature dictionary
            for i, val in enumerate(ember_features):
                features[f'ember_{i}'] = val
        except Exception as e:
            print(f"Error extracting EMBER features from {file_path}: {e}")
    
    return features

def extract_elf_features(file_path):
    """Extract features from ELF files"""
    features = {}
    
    # Basic file info
    file_size = os.path.getsize(file_path)
    features['file_size'] = file_size
    
    # Calculate entropy of the whole file
    with open(file_path, 'rb') as f:
        data = f.read()
        features['entropy'] = calculate_entropy(data)
    
    # Use pyelftools for detailed ELF analysis if available
        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Header information
                features['elf_type'] = elf.header.e_type
                features['machine_type'] = elf.header.e_machine
                features['entry_point'] = elf.header.e_entry
                
                # Section information
                section_entropies = []
                section_sizes = []
                executable_sections = 0
                
                for section in elf.iter_sections():
                    try:
                        section_data = section.data()
                        section_entropies.append(calculate_entropy(section_data))
                        section_sizes.append(len(section_data))
                        if section.header.sh_flags & 0x4:  # Check if section is executable
                            executable_sections += 1
                    except Exception:
                        pass
                
                features['number_of_sections'] = elf.num_sections()
                features['avg_section_entropy'] = np.mean(section_entropies) if section_entropies else 0
                features['max_section_entropy'] = max(section_entropies) if section_entropies else 0
                features['avg_section_size'] = np.mean(section_sizes) if section_sizes else 0
                features['executable_sections'] = executable_sections
                
                # Symbol information
                symbol_count = 0
                try:
                    symbol_section = elf.get_section_by_name('.symtab')
                    if symbol_section:
                        symbol_count = symbol_section.num_symbols()
                except Exception:
                    pass
                
                features['number_of_symbols'] = symbol_count
                
                # Program header information
                features['number_of_segments'] = elf.num_segments()
                
        except Exception as e:
            print(f"Error analyzing ELF file {file_path}: {e}")
            # Set default values for all ELF-specific features
            features['elf_type'] = 0
            features['machine_type'] = 0
            features['entry_point'] = 0
            features['number_of_sections'] = 0
            features['avg_section_entropy'] = 0
            features['max_section_entropy'] = 0
            features['avg_section_size'] = 0
            features['executable_sections'] = 0
            features['number_of_symbols'] = 0
            features['number_of_segments'] = 0
    
    return features

def extract_strings(file_path):
    """Extract strings from a binary file"""
    strings_result = {}
    
    # Extract ASCII strings
    strings_raw = subprocess.run(["strings", file_path], capture_output=True, text=True)
    ascii_strings = strings_raw.stdout.split("\n")
    ascii_strings = [s.strip() for s in ascii_strings if len(s) >= 4]
    
    # Extract Unicode strings (if on Linux)
    unicode_strings = []
    try:
        unicode_raw = subprocess.run(["strings", "-el", file_path], capture_output=True, text=True)
        unicode_strings = unicode_raw.stdout.split("\n")
        unicode_strings = [s.strip() for s in unicode_strings if len(s) >= 4]
    except Exception:
        pass
    
    # Combine all strings
    all_strings = ascii_strings + unicode_strings
    
    # Count occurrences
    string_counts = Counter(all_strings)
    
    # Store top strings and their counts
    strings_result['all_strings'] = all_strings
    strings_result['string_counts'] = string_counts
    strings_result['top_strings'] = string_counts.most_common(50)
    
    # Calculate some string-based features
    strings_result['string_count'] = len(all_strings)
    strings_result['unique_string_count'] = len(string_counts)
    strings_result['avg_string_length'] = np.mean([len(s) for s in all_strings]) if all_strings else 0
    
    # Check for suspicious strings
    suspicious_keywords = ['http://', 'https://', 'socket', 'encrypt', 'decrypt', 'password', 
                          'admin', 'login', 'registry', 'inject', 'shellcode', 'payload']
    
    suspicious_count = sum(1 for s in all_strings if any(keyword in s.lower() for keyword in suspicious_keywords))
    strings_result['suspicious_string_count'] = suspicious_count
    
    return strings_result

def check_virustotal(file_hash):
    """Check a file hash against VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API check not available"}
    
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            return {
                "found": True,
                "malicious": result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                "total": result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("total", 0),
                "data": result.get("data", {})  # Return the full data for detailed analysis
            }
        elif response.status_code == 404:
            return {"found": False}
        else:
            return {"error": f"API error: {response.status_code}"}
    
    except Exception as e:
        return {"error": str(e)}

def get_detailed_virustotal_info(file_hash):
    """Get detailed information about a file from VirusTotal API including malware family"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API check not available"}
    
    try:
        # Get file report
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            attributes = result.get("data", {}).get("attributes", {})
            
            # Extract detection details
            last_analysis_results = attributes.get("last_analysis_results", {})
            
            # Extract potential malware family names from AV detections
            family_names = []
            for engine, detection in last_analysis_results.items():
                if detection.get("category") == "malicious" and detection.get("result"):
                    family_names.append(detection.get("result").lower())
            
            # Count occurrences of family names
            family_counter = Counter(family_names)
            
            # Get the most common family names
            common_families = family_counter.most_common(5)
            
            # Extract meaningful tags
            tags = attributes.get("tags", [])
            
            return {
                "found": True,
                "malicious": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "total": attributes.get("last_analysis_stats", {}).get("total", 0),
                "detection_rate": attributes.get("last_analysis_stats", {}).get("malicious", 0) / 
                                 attributes.get("last_analysis_stats", {}).get("total", 1),
                "family_candidates": common_families,
                "tags": tags,
                "type_description": attributes.get("type_description", ""),
                "file_type": attributes.get("type_tag", ""),
                "names": attributes.get("names", []),
                "creation_date": attributes.get("creation_date", None)
            }
        elif response.status_code == 404:
            return {"found": False}
        else:
            return {"error": f"API error: {response.status_code}"}
    
    except Exception as e:
        return {"error": str(e)}

def search_virustotal_for_samples(query, limit=10):
    """Search VirusTotal for samples matching a query"""
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API check not available"}
    
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
    if not VIRUSTOTAL_API_KEY:
        return {"error": "VirusTotal API check not available"}
    
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

def extract_all_features(file_path):
    """Extract all features from a binary file"""
    features = {}
    
    # Get file type
    file_type = get_file_type(file_path)
    features['file_type'] = file_type
    
    # Extract type-specific features
    if file_type == "PE":
        pe_features = extract_pe_features(file_path)
        features.update(pe_features)
    elif file_type == "ELF":
        elf_features = extract_elf_features(file_path)
        features.update(elf_features)
    
    # Extract strings
    strings_data = extract_strings(file_path)
    features['string_count'] = strings_data['string_count']
    features['unique_string_count'] = strings_data['unique_string_count']
    features['avg_string_length'] = strings_data['avg_string_length']
    features['suspicious_string_count'] = strings_data['suspicious_string_count']
    
    # Calculate file hash and check VirusTotal if API key is available
    file_hash = calculate_file_hash(file_path)
    features['file_hash'] = file_hash
    
    if VIRUSTOTAL_API_KEY:
        vt_result = check_virustotal(file_hash)
        if 'found' in vt_result and vt_result['found']:
            features['vt_found'] = 1
            features['vt_malicious'] = vt_result['malicious']
            features['vt_detection_rate'] = vt_result['malicious'] / vt_result['total'] if vt_result['total'] > 0 else 0
        else:
            features['vt_found'] = 0
            features['vt_malicious'] = 0
            features['vt_detection_rate'] = 0
    
    return features

#######################
# CLASSIFICATION
#######################

def build_cnn_model():
    """Build a CNN model for image-based classification"""
    model = keras.Sequential([
        layers.Input(shape=(IMG_SIZE, IMG_SIZE, 1)),  # Ensure consistent input image sizes
        layers.Rescaling(1.0/255),
        layers.Conv2D(32, (3, 3), activation='relu', input_shape=(IMG_SIZE, IMG_SIZE, 1)),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu'),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu'),
        layers.MaxPooling2D((2, 2)),
        layers.Flatten(),
        layers.Dense(128, activation='relu'),
        layers.Dropout(0.5),  # Increased dropout to prevent overfitting
        layers.Dense(len(LABELS), activation='softmax')
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model

def data_augmentation(images):
    """Apply data augmentation to images"""
    data_aug_layers = [
        layers.RandomFlip("horizontal_and_vertical"),
        layers.RandomRotation(0.3),
        layers.RandomZoom(0.2),
        layers.RandomContrast(0.2),
        layers.RandomTranslation(0.1, 0.1),
        # Add noise
        layers.GaussianNoise(0.05),
    ]
    
    for layer in data_aug_layers:
        images = layer(images)
    return images

def generate_synthetic_samples(training_dir, samples_per_class=100):
    """Generate synthetic samples for each class to increase dataset size"""
    print("Generating synthetic samples...")
    
    # For each class directory
    for label in os.listdir(training_dir):
        label_dir = os.path.join(training_dir, label)
        
        if not os.path.isdir(label_dir):
            continue
        
        print(f"Processing {label} samples...")
        
        # Get list of existing files
        existing_files = [f for f in os.listdir(label_dir) if os.path.isfile(os.path.join(label_dir, f))]
        
        if not existing_files:
            print(f"  No files found in {label_dir}")
            continue
        
        # Calculate how many synthetic samples to generate per existing file
        num_existing = len(existing_files)
        samples_per_file = max(1, samples_per_class // num_existing)
        
        print(f"  Found {num_existing} existing files, generating {samples_per_file} synthetic samples per file")
        
        # For each existing file
        for file_name in existing_files:
            file_path = os.path.join(label_dir, file_name)
            
            # Read the file content
            with open(file_path, 'rb') as f:
                content = bytearray(f.read())
            
            # Generate synthetic samples
            for i in range(samples_per_file):
                # Create a copy of the content
                synthetic_content = bytearray(content)
                
                # Apply random modifications
                # 1. Modify a small percentage of bytes (1-5%)
                num_bytes_to_modify = max(1, int(len(synthetic_content) * (0.01 + 0.04 * np.random.random())))
                for _ in range(num_bytes_to_modify):
                    idx = np.random.randint(0, len(synthetic_content))
                    synthetic_content[idx] = np.random.randint(0, 256)
                
                # 2. Insert a small number of random bytes (0-2%)
                if len(synthetic_content) > 100:  # Only if file is large enough
                    num_bytes_to_insert = int(len(synthetic_content) * (0.02 * np.random.random()))
                    for _ in range(num_bytes_to_insert):
                        idx = np.random.randint(0, len(synthetic_content))
                        synthetic_content.insert(idx, np.random.randint(0, 256))
                
                # 3. Remove a small number of bytes (0-2%)
                if len(synthetic_content) > 100:  # Only if file is large enough
                    num_bytes_to_remove = int(len(synthetic_content) * (0.02 * np.random.random()))
                    for _ in range(num_bytes_to_remove):
                        if len(synthetic_content) > 1:  # Ensure we don't remove all bytes
                            idx = np.random.randint(0, len(synthetic_content))
                            del synthetic_content[idx]
                
                # Save the synthetic sample
                synthetic_file_name = f"synthetic_{file_name}_{i}"
                synthetic_file_path = os.path.join(label_dir, synthetic_file_name)
                
                with open(synthetic_file_path, 'wb') as f:
                    f.write(synthetic_content)
                
                print(f"    Created synthetic sample: {synthetic_file_name}")
                
                # Create grayscale image for the synthetic sample
                create_greyscale_image(synthetic_file_path, label=label, file_name=synthetic_file_name, train=True)
    
    print("Synthetic sample generation complete.")

def prepare_image_dataset():
    """Prepare image dataset for CNN training"""
    # Create image dataset from directory
    training_dataset, val_dataset = keras.utils.image_dataset_from_directory(
        IMG_TRAIN_DIR,
        validation_split=0.2,
        subset='both',
        seed=42,
        image_size=(IMG_SIZE, IMG_SIZE),
        batch_size=BATCH_SIZE,
        label_mode='categorical',
        color_mode='grayscale'
    )
    
    # Apply data augmentation
    augmented_training_dataset = training_dataset.map(
        lambda img, label: (data_augmentation(img), label)
    )
    
    return augmented_training_dataset, val_dataset

def train_cnn_model(epochs=10):
    """Train CNN model on image data"""
    print("Preparing image dataset...")
    augmented_training_dataset, val_dataset = prepare_image_dataset()
    
    print("Building and training CNN model...")
    model = build_cnn_model()
    model.fit(
        augmented_training_dataset, 
        epochs=epochs, 
        validation_data=val_dataset,
        callbacks=[
            keras.callbacks.EarlyStopping(patience=3, restore_best_weights=True)
        ]
    )
    
    # Save the model
    model.save('malware_classifier.h5')
    print("CNN model saved as 'malware_classifier.h5'")
    
    return model

def classify_samples_cnn(model=None):
    """Classify samples using CNN model"""
    if model is None:
        try:
            model = keras.models.load_model('malware_classifier.h5')
        except:
            print("No model found. Please train the model first.")
            return None
    
    results = []
    for file in os.listdir(DIR):
        file_path = os.path.join(DIR, file)
        greyscale_img = create_greyscale_image(file_path, file_name=file, train=False)
        img_array = keras.utils.img_to_array(greyscale_img)
        img_array = img_array.reshape(1, IMG_SIZE, IMG_SIZE, 1)
        
        pred_probs = model.predict(img_array)
        pred_label = np.argmax(pred_probs)
        confidence = np.max(pred_probs)
        
        results.append({
            'filename': file,
            'label': INV_LABELS[pred_label],
            'confidence': float(confidence)
        })
    
    # Save results to CSV
    df = pd.DataFrame(results)
    df.to_csv("results/cnn_classification.csv", index=False)
    
    # Print summary
    print("\n--- CNN Classification Results ---")
    for label in LABELS.keys():
        count = sum(1 for r in results if r['label'] == label)
        print(f"{label}: {count} samples ({count/len(results)*100:.2f}%)")
    
    return results

def classify_samples_static():
    """Classify samples using static analysis features"""
    print("Extracting static features for classification...")
    
    features_list = []
    filenames = []
    
    for file in os.listdir(DIR):
        file_path = os.path.join(DIR, file)
        print(f"Analyzing {file}...")
        
        # Extract features
        features = extract_all_features(file_path)
        
        # Convert features to a flat list (excluding non-numeric and specific fields)
        exclude_keys = ['file_hash', 'file_type', 'all_strings', 'string_counts', 'top_strings']
        feature_vector = []
        
        for key, value in features.items():
            if key not in exclude_keys and isinstance(value, (int, float)):
                feature_vector.append(value)
        
        features_list.append(feature_vector)
        filenames.append(file)
    
    # Convert to numpy array
    X = np.array(features_list)
    
    # Simple heuristic classification based on features
    results = []
    
    for i, file in enumerate(filenames):
        features = X[i]
        
        # Simple heuristic: classify based on entropy, suspicious strings, and executable sections
        entropy = features[1]  # Assuming entropy is the second feature
        suspicious_strings = features[4]  # Assuming suspicious_string_count is the fifth feature
        
        # Higher score means more likely to be malicious
        malicious_score = entropy * 0.5 + suspicious_strings * 0.5
        
        # Determine label based on score thresholds (these thresholds are arbitrary and should be tuned)
        if malicious_score < 3:
            label = "benign"
        elif malicious_score < 4:
            label = "malicious1"
        elif malicious_score < 5:
            label = "malicious2"
        elif malicious_score < 6:
            label = "malicious3"
        else:
            label = "malicious4"
        
        results.append({
            'filename': file,
            'label': label,
            'malicious_score': malicious_score
        })
    
    # Save results to CSV
    df = pd.DataFrame(results)
    df.to_csv("results/static_classification.csv", index=False)
    
    # Print summary
    print("\n--- Static Analysis Classification Results ---")
    for label in LABELS.keys():
        count = sum(1 for r in results if r['label'] == label)
        print(f"{label}: {count} samples ({count/len(results)*100:.2f}%)")
    
    return results

def combine_classifications(cnn_results, static_results):
    """Combine CNN and static analysis results"""
    combined_results = []
    
    for cnn_result, static_result in zip(cnn_results, static_results):
        assert cnn_result['filename'] == static_result['filename'], "Filename mismatch in results"
        
        filename = cnn_result['filename']
        
        # If CNN and static analysis agree, use that label
        if cnn_result['label'] == static_result['label']:
            final_label = cnn_result['label']
        else:
            # If they disagree, use the CNN label if confidence is high, otherwise use static
            if cnn_result['confidence'] > 0.8:
                final_label = cnn_result['label']
            else:
                final_label = static_result['label']
        
        combined_results.append({
            'filename': filename,
            'label': final_label,
            'cnn_label': cnn_result['label'],
            'static_label': static_result['label'],
            'cnn_confidence': cnn_result['confidence'],
            'static_score': static_result['malicious_score']
        })
    
    # Save results to CSV
    df = pd.DataFrame(combined_results)
    df.to_csv("results/combined_classification.csv", index=False)
    
    # Print summary
    print("\n--- Combined Classification Results ---")
    for label in LABELS.keys():
        count = sum(1 for r in combined_results if r['label'] == label)
        print(f"{label}: {count} samples ({count/len(combined_results)*100:.2f}%)")
    
    return combined_results

#######################
# CLUSTERING
#######################

def extract_clustering_features():
    """Extract features for clustering"""
    print("Extracting features for clustering...")
    
    features_list = []
    filenames = []
    
    for file in os.listdir(DIR):
        file_path = os.path.join(DIR, file)
        print(f"Analyzing {file} for clustering...")
        
        # Extract features
        features = extract_all_features(file_path)
        
        # Convert features to a flat list (excluding non-numeric and specific fields)
        exclude_keys = ['file_hash', 'file_type', 'all_strings', 'string_counts', 'top_strings']
        feature_vector = []
        
        for key, value in features.items():
            if key not in exclude_keys and isinstance(value, (int, float)):
                feature_vector.append(value)
        
        features_list.append(feature_vector)
        filenames.append(file)
    
    # Convert to numpy array
    X = np.array(features_list)
    
    # Normalize features
    X_normalized = normalize(X, norm='l2')
    
    # Apply PCA for dimensionality reduction
    pca = PCA(n_components=min(10, X.shape[1]))
    X_pca = pca.fit_transform(X_normalized)
    
    return X_pca, filenames

def analyze_clusters(X, filenames, cluster_results, original_features=None):
    """Analyze clustering results in detail"""
    print("Analyzing cluster properties in detail...")
    
    # Group files by cluster
    clusters = {}
    for i, result in enumerate(cluster_results):
        cluster = result['cluster']
        filename = result['filename']
        
        if cluster not in clusters:
            clusters[cluster] = {'files': [], 'indices': []}
        
        clusters[cluster]['files'].append(filename)
        clusters[cluster]['indices'].append(i)
    
    # Calculate cluster statistics
    cluster_stats = {}
    for cluster, data in clusters.items():
        indices = data['indices']
        cluster_X = X[indices]
        
        # Calculate centroid
        centroid = np.mean(cluster_X, axis=0)
        
        # Calculate distances to centroid
        distances = np.linalg.norm(cluster_X - centroid, axis=1)
        
        # Find representative samples (closest to centroid)
        closest_indices = np.argsort(distances)[:3]
        representative_files = [data['files'][i] for i in closest_indices]
        
        # Calculate intra-cluster distance statistics
        cluster_stats[cluster] = {
            'size': len(indices),
            'centroid': centroid,
            'avg_distance': np.mean(distances),
            'max_distance': np.max(distances),
            'std_distance': np.std(distances),
            'representative_files': representative_files
        }
        
        # If original features are provided, calculate feature statistics
        if original_features is not None:
            cluster_features = original_features[indices]
            feature_means = np.mean(cluster_features, axis=0)
            feature_stds = np.std(cluster_features, axis=0)
            
            cluster_stats[cluster]['feature_means'] = feature_means
            cluster_stats[cluster]['feature_stds'] = feature_stds
    
    # Save detailed analysis to CSV
    detailed_results = []
    for cluster, stats in cluster_stats.items():
        for file in clusters[cluster]['files']:
            detailed_results.append({
                'filename': file,
                'cluster': cluster,
                'cluster_size': stats['size'],
                'avg_distance': stats['avg_distance'],
                'representative': file in stats['representative_files']
            })
    
    df = pd.DataFrame(detailed_results)
    df.to_csv("results/cluster_analysis.csv", index=False)
    
    # Print summary
    print("\n--- Cluster Analysis Results ---")
    for cluster, stats in sorted(cluster_stats.items()):
        print(f"Cluster {cluster}: {stats['size']} samples")
        print(f"  Average distance to centroid: {stats['avg_distance']:.4f}")
        print(f"  Representative samples: {', '.join(stats['representative_files'])}")
        print()
    
    return cluster_stats

def perform_kmeans_clustering(X, filenames, n_clusters=5, analyze=True):
    """Perform K-means clustering"""
    print(f"Performing K-means clustering with {n_clusters} clusters...")
    
    kmeans = KMeans(n_clusters=n_clusters, n_init=10, random_state=42)
    cluster_labels = kmeans.fit_predict(X)
    
    # Calculate silhouette score
    if len(set(cluster_labels)) > 1:  # Need at least 2 clusters for silhouette score
        silhouette = silhouette_score(X, cluster_labels)
        print(f"K-means silhouette score: {silhouette:.4f}")
    
    # Create results
    results = []
    for i, file in enumerate(filenames):
        results.append({
            'filename': file,
            'cluster': int(cluster_labels[i])
        })
    
    # Save results to CSV
    df = pd.DataFrame(results)
    df.to_csv("results/kmeans_clustering.csv", index=False)
    
    # Print summary
    print("\n--- K-means Clustering Results ---")
    cluster_counts = Counter(cluster_labels)
    for cluster, count in sorted(cluster_counts.items()):
        print(f"Cluster {cluster}: {count} samples ({count/len(cluster_labels)*100:.2f}%)")
    
    # Analyze clusters if requested
    if analyze:
        cluster_stats = analyze_clusters(X, filenames, results)
    
    return results

def perform_dbscan_clustering(X, filenames):
    """Perform DBSCAN clustering with parameter optimization"""
    print("Performing DBSCAN clustering with parameter optimization...")
    
    # Try different eps values to find the best one
    eps_values = np.linspace(0.00002, 0.007, 2500)
    best_eps = None
    best_score = -1
    best_labels = None
    
    for eps in eps_values:
        dbscan = DBSCAN(eps=eps, min_samples=3)
        labels = dbscan.fit_predict(X)
        
        # Skip if all samples are noise (-1) or all in one cluster
        if len(set(labels)) <= 1 or -1 in labels:
            continue
        
        # Calculate silhouette score
        try:
            score = silhouette_score(X, labels)
            if score > best_score:
                best_score = score
                best_eps = eps
                best_labels = labels
        except:
            continue
    
    # If no good parameters found, use default
    if best_labels is None:
        print("Could not find optimal DBSCAN parameters. Using default.")
        dbscan = DBSCAN(eps=0.5, min_samples=3)
        best_labels = dbscan.fit_predict(X)
    else:
        print(f"Best DBSCAN eps: {best_eps:.4f}, silhouette score: {best_score:.4f}")
    
    # Create results
    results = []
    for i, file in enumerate(filenames):
        results.append({
            'filename': file,
            'cluster': int(best_labels[i])
        })
    
    # Save results to CSV
    df = pd.DataFrame(results)
    df.to_csv("results/dbscan_clustering.csv", index=False)
    
    # Print summary
    print("\n--- DBSCAN Clustering Results ---")
    cluster_counts = Counter(best_labels)
    for cluster, count in sorted(cluster_counts.items()):
        print(f"Cluster {cluster}: {count} samples ({count/len(best_labels)*100:.2f}%)")
    
    return results

#######################
# CLUSTER VERIFICATION
#######################

def verify_clusters_with_virustotal(cluster_results, num_samples=3):
    """Verify cluster assignments using VirusTotal API"""
    print("Verifying clusters using VirusTotal API...")
    
    if VIRUSTOTAL_API_KEY:
        print("Error: VirusTotal API check not available. Please provide a valid API key.")
        return None
    
    # Group files by cluster
    clusters = {}
    for result in cluster_results:
        cluster = result['cluster']
        filename = result['filename']
        
        if cluster not in clusters:
            clusters[cluster] = []
        
        clusters[cluster].append(filename)
    
    # Analyze representative samples from each cluster
    cluster_info = {}
    for cluster, files in clusters.items():
        print(f"Analyzing cluster {cluster} with {len(files)} samples...")
        
        # Select representative samples (or use all if fewer than num_samples)
        sample_files = files[:min(num_samples, len(files))]
        
        # Get detailed VT info for each sample
        family_candidates = []
        tags_list = []
        file_types = []
        
        for file in sample_files:
            file_path = os.path.join(DIR, file)
            file_hash = calculate_file_hash(file_path)
            
            print(f"  Checking {file} ({file_hash}) on VirusTotal...")
            vt_info = get_detailed_virustotal_info(file_hash)
            
            if 'found' in vt_info and vt_info['found']:
                # Add family candidates
                if 'family_candidates' in vt_info:
                    family_candidates.extend([fc[0] for fc in vt_info['family_candidates']])
                
                # Add tags
                if 'tags' in vt_info:
                    tags_list.extend(vt_info['tags'])
                
                # Add file type
                if 'file_type' in vt_info:
                    file_types.append(vt_info['file_type'])
            
            # Sleep to respect API rate limits
            time.sleep(2)
        
        # Count occurrences
        family_counter = Counter(family_candidates)
        tags_counter = Counter(tags_list)
        file_type_counter = Counter(file_types)
        
        # Get the most common values
        common_families = family_counter.most_common(3)
        common_tags = tags_counter.most_common(5)
        common_file_type = file_type_counter.most_common(1)
        
        # Store cluster information
        cluster_info[cluster] = {
            'size': len(files),
            'common_families': common_families,
            'common_tags': common_tags,
            'common_file_type': common_file_type[0][0] if common_file_type else "unknown",
            'is_benign': any('benign' in tag.lower() for tag in tags_list) or 
                        any('clean' in family.lower() for family in family_candidates)
        }
    
    # Determine cluster labels based on VT info
    cluster_labels = {}
    
    # First, identify the benign cluster
    benign_candidates = []
    for cluster, info in cluster_info.items():
        if info['is_benign']:
            benign_candidates.append((cluster, info['size']))
    
    # If we found benign candidates, use the largest one as benign
    if benign_candidates:
        benign_cluster = max(benign_candidates, key=lambda x: x[1])[0]
        cluster_labels[benign_cluster] = "benign"
    else:
        # If no clear benign cluster, use the one with lowest detection rate
        # This is a fallback and might not be accurate
        benign_cluster = min(cluster_info.keys(), key=lambda c: len(cluster_info[c]['common_families']))
        cluster_labels[benign_cluster] = "benign"
    
    # Assign labels to malicious clusters
    malware_idx = 1
    for cluster in sorted(cluster_info.keys()):
        if cluster not in cluster_labels:
            cluster_labels[cluster] = f"malicious{malware_idx}"
            malware_idx += 1
    
    # Save results to CSV
    results = []
    for result in cluster_results:
        cluster = result['cluster']
        filename = result['filename']
        
        # Get cluster info
        info = cluster_info.get(cluster, {})
        common_families = info.get('common_families', [])
        common_tags = info.get('common_tags', [])
        
        results.append({
            'filename': filename,
            'cluster': cluster,
            'label': cluster_labels.get(cluster, "unknown"),
            'common_families': ';'.join([f"{family}:{count}" for family, count in common_families]),
            'common_tags': ';'.join([f"{tag}:{count}" for tag, count in common_tags])
        })
    
    df = pd.DataFrame(results)
    df.to_csv("results/cluster_verification.csv", index=False)
    
    # Print summary
    print("\n--- Cluster Verification Results ---")
    for cluster, label in sorted(cluster_labels.items()):
        info = cluster_info[cluster]
        print(f"Cluster {cluster} -> {label}")
        print(f"  Size: {info['size']} samples")
        print(f"  Common families: {', '.join([f'{family}({count})' for family, count in info['common_families']])}")
        print(f"  Common tags: {', '.join([f'{tag}({count})' for tag, count in info['common_tags']])}")
        print(f"  Common file type: {info['common_file_type']}")
        print()
    
    return {
        'cluster_labels': cluster_labels,
        'cluster_info': cluster_info
    }

#######################
# TRAINING DATASET CREATION
#######################

def download_training_dataset(cluster_verification, samples_per_family=10):
    """Download a balanced training dataset based on identified families"""
    print("Downloading training dataset from VirusTotal...")
    
    if not VIRUSTOTAL_API_KEY:
        print("Error: VirusTotal API check not available. Please provide a valid API key.")
        return False
    
    # Create training dataset directory
    training_dir = "./training_dataset"
    os.makedirs(training_dir, exist_ok=True)
    
    # Get cluster labels and info
    cluster_labels = cluster_verification['cluster_labels']
    cluster_info = cluster_verification['cluster_info']
    
    # Download samples for each label
    for cluster, label in cluster_labels.items():
        print(f"Downloading samples for {label} (cluster {cluster})...")
        
        # Create directory for this label
        label_dir = os.path.join(training_dir, label)
        os.makedirs(label_dir, exist_ok=True)
        
        # Construct search query based on cluster info
        info = cluster_info[cluster]
        
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
        
        if 'error' in search_result:
            print(f"  Error searching for samples: {search_result['error']}")
            continue
        
        file_hashes = search_result.get('file_hashes', [])
        print(f"  Found {len(file_hashes)} samples")
        
        # Download each sample
        for i, file_hash in enumerate(file_hashes):
            print(f"  Downloading sample {i+1}/{len(file_hashes)}: {file_hash}")
            
            download_result = download_sample_from_virustotal(file_hash, label_dir)
            
            if 'error' in download_result:
                print(f"    Error downloading sample: {download_result['error']}")
            else:
                print(f"    Downloaded to {download_result['file_path']}")
            
            # Sleep to respect API rate limits
            time.sleep(2)
    
    print("Training dataset download complete.")
    return True

def prepare_training_dataset():
    """Prepare the downloaded samples for training"""
    print("Preparing training dataset...")
    
    # Check if training dataset exists
    training_dir = "./training_dataset"
    if not os.path.exists(training_dir):
        print("Error: Training dataset directory not found.")
        return False
    
    # Create images for each sample
    for label in os.listdir(training_dir):
        label_dir = os.path.join(training_dir, label)
        
        if not os.path.isdir(label_dir):
            continue
        
        print(f"Processing {label} samples...")
        
        for file in os.listdir(label_dir):
            file_path = os.path.join(label_dir, file)
            
            if os.path.isfile(file_path):
                print(f"  Creating image for {file}")
                create_greyscale_image(file_path, label=label, file_name=file, train=True)
    
    print("Training dataset preparation complete.")
    return True

#######################
# COMPLETE WORKFLOW
#######################

def run_complete_workflow(n_clusters=5, samples_per_family=10):
    """Run the complete workflow from clustering to training dataset creation"""
    print("Running complete malware analysis workflow...")
    
    # Step 1: Initialize directories
    init_directories()
    
    # Step 2: Extract features and perform clustering
    X, filenames = extract_clustering_features()
    clustering_results = perform_kmeans_clustering(X, filenames, n_clusters=n_clusters)
    
    # Step 3: Analyze clusters
    cluster_stats = analyze_clusters(X, filenames, clustering_results)
    
    # Step 4: Verify clusters with VirusTotal
    cluster_verification = verify_clusters_with_virustotal(clustering_results)
    
    if not cluster_verification:
        print("Error: Cluster verification failed.")
        return False
    
    # Step 5: Download training samples
    download_success = download_training_dataset(cluster_verification, samples_per_family)
    
    if not download_success:
        print("Error: Training dataset download failed.")
        return False
    
    # Step 6: Prepare training dataset
    prepare_success = prepare_training_dataset()
    
    if not prepare_success:
        print("Error: Training dataset preparation failed.")
        return False
    
    # Step 7: Generate YARA rules
    generate_yara_rules(clustering_results)
    
    print("Complete workflow finished successfully.")
    return True

#######################
# YARA RULE GENERATION
#######################

def setup_yargen():
    """Set up yarGen for YARA rule generation"""
    print("Setting up yarGen...")
    
    # Check if yarGen is already cloned
    if not os.path.exists("./yarGen"):
        print("Cloning yarGen repository...")
        subprocess.run(["git", "clone", "https://github.com/Neo23x0/yarGen.git"], check=True)
        
        # Install dependencies
        print("Installing yarGen dependencies...")
        subprocess.run(["pip", "install", "-r", "./yarGen/requirements.txt"], check=True)
    
    print("yarGen setup complete.")

def generate_yara_rules(cluster_results):
    """Generate YARA rules for each malware family (cluster)"""
    print("Generating YARA rules for each malware family...")
    
    # Ensure yarGen is set up
    setup_yargen()
    
    # Create directory for YARA rules
    os.makedirs("./yara_rules", exist_ok=True)
    
    # Group files by cluster
    clusters = {}
    for result in cluster_results:
        cluster = result['cluster']
        filename = result['filename']
        
        if cluster not in clusters:
            clusters[cluster] = []
        
        clusters[cluster].append(filename)
    
    # Generate YARA rules for each cluster
    for cluster, files in clusters.items():
        print(f"Generating YARA rules for cluster {cluster} with {len(files)} samples...")
        
        # Create a directory for this cluster's samples
        cluster_dir = f"./cluster_{cluster}"
        os.makedirs(cluster_dir, exist_ok=True)
        
        # Copy files to cluster directory
        for file in files:
            src_path = os.path.join(DIR, file)
            dst_path = os.path.join(cluster_dir, file)
            subprocess.run(["cp", src_path, dst_path], check=True)
        
        # Generate YARA rule using yarGen
        rule_file = f"./yara_rules/cluster_{cluster}_rule.yar"
        try:
            subprocess.run([
                "python", "./yarGen/yarGen.py",
                "-m", cluster_dir,
                "-o", rule_file,
                "-a", "Malware Analyst",
                "-p", f"MALWARE_FAMILY_{cluster}"
            ], check=True)
            
            print(f"YARA rule generated: {rule_file}")
        except Exception as e:
            print(f"Error generating YARA rule for cluster {cluster}: {e}")
        
        # Clean up
        subprocess.run(["rm", "-rf", cluster_dir], check=True)
    
    print("YARA rule generation complete.")
    return True

#######################
# MAIN FUNCTION
#######################

def main():
    """Main function with command-line argument parsing"""
    parser = argparse.ArgumentParser(description="Malware Classification and Clustering Tool")
    
    # General options
    parser.add_argument("--init", action="store_true", help="Initialize directories")
    
    # Dataset processing options
    parser.add_argument("--create-images", action="store_true", help="Create grayscale images from binaries")
    parser.add_argument("--label", type=str, help="Label for training images (required with --create-images)")
    
    # Classification options
    parser.add_argument("--train-cnn", action="store_true", help="Train CNN model")
    parser.add_argument("--epochs", type=int, default=10, help="Number of epochs for CNN training")
    parser.add_argument("--classify-cnn", action="store_true", help="Classify samples using CNN")
    parser.add_argument("--classify-static", action="store_true", help="Classify samples using static analysis")
    parser.add_argument("--classify-combined", action="store_true", help="Classify samples using combined approach")
    
    # Clustering options
    parser.add_argument("--cluster", action="store_true", help="Perform clustering")
    parser.add_argument("--kmeans", action="store_true", help="Use K-means clustering")
    parser.add_argument("--dbscan", action="store_true", help="Use DBSCAN clustering")
    parser.add_argument("--n-clusters", type=int, default=5, help="Number of clusters for K-means")
    parser.add_argument("--analyze-clusters", action="store_true", help="Analyze clustering results in detail")
    
    # VirusTotal integration options
    parser.add_argument("--verify-clusters", action="store_true", help="Verify clusters using VirusTotal API")
    parser.add_argument("--download-training", action="store_true", help="Download training dataset from VirusTotal")
    parser.add_argument("--samples-per-family", type=int, default=35, help="Number of samples to download per family")
    parser.add_argument("--prepare-training", action="store_true", help="Prepare downloaded training dataset")
    
    # YARA options
    parser.add_argument("--generate-yara", action="store_true", help="Generate YARA rules")
    
    # API options
    parser.add_argument("--vt-api-key", type=str, help="VirusTotal API key")
    
    # Complete workflow
    parser.add_argument("--run-workflow", action="store_true", help="Run complete analysis workflow")
    
    # Import time module for API rate limiting
    import time
    
    args = parser.parse_args()
    
    # Set VirusTotal API key if provided
    global VIRUSTOTAL_API_KEY
    if args.vt_api_key:
        VIRUSTOTAL_API_KEY = args.vt_api_key
    
    # Run complete workflow if requested
    if args.run_workflow:
        run_complete_workflow(n_clusters=args.n_clusters, samples_per_family=args.samples_per_family)
        return
    
    # Initialize directories if requested
    if args.init:
        init_directories()
        print("Directories initialized.")
    
    # Create grayscale images if requested
    if args.create_images:
        if not args.label:
            print("Error: --label is required with --create-images")
            return
        
        print(f"Creating grayscale images with label '{args.label}'...")
        for file in os.listdir(DIR):
            file_path = os.path.join(DIR, file)
            create_greyscale_image(file_path, label=args.label, file_name=file, train=True)
        
        print("Grayscale images created.")
    
    # Train CNN model if requested
    if args.train_cnn:
        train_cnn_model(epochs=args.epochs)
    
    # Classification
    cnn_results = None
    static_results = None
    
    if args.classify_cnn:
        cnn_results = classify_samples_cnn()
    
    if args.classify_static:
        static_results = classify_samples_static()
    
    if args.classify_combined:
        if cnn_results is None:
            cnn_results = classify_samples_cnn()
        
        if static_results is None:
            static_results = classify_samples_static()
        
        combine_classifications(cnn_results, static_results)
    
    # Clustering
    clustering_results = None
    
    if args.cluster:
        X, filenames = extract_clustering_features()
        
        if args.kmeans:
            clustering_results = perform_kmeans_clustering(X, filenames, n_clusters=args.n_clusters, analyze=args.analyze_clusters)
        
        if args.dbscan:
            clustering_results = perform_dbscan_clustering(X, filenames)
            
            # Analyze DBSCAN clusters if requested
            if args.analyze_clusters and clustering_results:
                analyze_clusters(X, filenames, clustering_results)
    
    # Verify clusters with VirusTotal if requested
    cluster_verification = None
    if args.verify_clusters:
        if clustering_results is None and args.cluster:
            X, filenames = extract_clustering_features()
            clustering_results = perform_kmeans_clustering(X, filenames, n_clusters=args.n_clusters)
        
        if clustering_results:
            cluster_verification = verify_clusters_with_virustotal(clustering_results)
        else:
            print("Error: Clustering results required for cluster verification.")
    
    # Download training dataset if requested
    if args.download_training:
        if cluster_verification is None and args.verify_clusters:
            if clustering_results is None and args.cluster:
                X, filenames = extract_clustering_features()
                clustering_results = perform_kmeans_clustering(X, filenames, n_clusters=args.n_clusters)
            
            if clustering_results:
                cluster_verification = verify_clusters_with_virustotal(clustering_results)
        
        if cluster_verification:
            download_training_dataset(cluster_verification, samples_per_family=args.samples_per_family)
        else:
            print("Error: Cluster verification required for downloading training dataset.")
    
    # Prepare training dataset if requested
    if args.prepare_training:
        prepare_training_dataset()
    
    # Generate YARA rules if requested
    if args.generate_yara:
        if clustering_results is None and args.cluster:
            X, filenames = extract_clustering_features()
            clustering_results = perform_kmeans_clustering(X, filenames, n_clusters=args.n_clusters)
        
        if clustering_results:
            generate_yara_rules(clustering_results)
        else:
            print("Error: Clustering results required for YARA rule generation.")
    
    print("All tasks completed.")

if __name__ == "__main__":
    main()
