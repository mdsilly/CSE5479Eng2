# Malware Classification and Clustering Tool

This tool provides a comprehensive approach to malware classification and clustering, combining multiple techniques:

1. Image-based classification using CNN
2. Static analysis of file headers, entropy, and strings
3. Clustering using KMeans and DBSCAN
4. YARA rule generation for identified malware families

## Requirements

The script will check for these dependencies and warn if they're missing:

- Python 3.6+
- TensorFlow/Keras
- scikit-learn
- numpy, pandas
- PIL (Pillow)
- pefile (for PE file analysis)
- pyelftools (for ELF file analysis)
- requests (for VirusTotal API)
- ember (for advanced PE feature extraction)

## Command-Line Arguments

The script supports modular execution through command-line arguments, allowing you to run specific parts of the analysis pipeline independently.

### General Options

```
--init                Initialize necessary directories
```

### Dataset Processing

```
--create-images       Create grayscale images from binaries
--label LABEL         Label for training images (required with --create-images)
```

### Classification Options

```
--train-cnn           Train CNN model on image data
--epochs EPOCHS       Number of epochs for CNN training (default: 10)
--classify-cnn        Classify samples using CNN
--classify-static     Classify samples using static analysis
--classify-combined   Classify samples using combined approach
```

### Clustering Options

```
--cluster             Perform clustering (required for --kmeans or --dbscan)
--kmeans              Use K-means clustering
--dbscan              Use DBSCAN clustering
--n-clusters N        Number of clusters for K-means (default: 5)
```

### YARA Options

```
--generate-yara       Generate YARA rules for identified clusters
```

### API Options

```
--vt-api-key KEY      VirusTotal API key for hash lookups
```

## Usage Examples

### Initial Setup

```bash
# Initialize directories
python script.py --init
```

### Creating Training Images

```bash
# Create grayscale images for benign samples
python script.py --create-images --label benign

# Create grayscale images for malicious samples
python script.py --create-images --label malicious1
```

### Training and Classification

```bash
# Train CNN model
python script.py --train-cnn --epochs 15

# Classify using CNN
python script.py --classify-cnn

# Classify using static analysis
python script.py --classify-static

# Classify using combined approach
python script.py --classify-combined
```

### Clustering

```bash
# Perform K-means clustering
python script.py --cluster --kmeans --n-clusters 5

# Perform DBSCAN clustering
python script.py --cluster --dbscan
```

### YARA Rule Generation

```bash
# Generate YARA rules based on clustering results
python script.py --cluster --kmeans --generate-yara
```

### Complete Analysis Pipeline

```bash
# Run the complete analysis pipeline
python script.py --init --classify-static --cluster --kmeans --dbscan --generate-yara
```

## Output Files

The script generates various output files in the `results/` directory:

- `cnn_classification.csv`: Results from CNN-based classification
- `static_classification.csv`: Results from static analysis classification
- `combined_classification.csv`: Results from combined classification approach
- `kmeans_clustering.csv`: Results from K-means clustering
- `dbscan_clustering.csv`: Results from DBSCAN clustering

YARA rules are generated in the `yara_rules/` directory.

## Notes

- For VirusTotal API integration, you need to provide your API key using the `--vt-api-key` parameter
- The script handles both PE (Windows) and ELF (Linux) executable formats
- For optimal results, train the CNN model with a balanced dataset of labeled samples
