import sys
import os
import numpy as np

# Completely disable TensorFlow for now
print("TensorFlow disabled due to compatibility issues")
TF_AVAILABLE = False
tf = None
keras = None
os.environ['TF_MIN_GPU_MULTIPROCESSOR_COUNT'] = '8'  # Disable GPU usage
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Disable GPU usage
print('yertttt')
try:
    from PIL import Image
except ImportError as e:
    print(f"Error importing PIL: {e}")
    sys.exit(1)

# Try to import TensorFlow with CPU-only support
print('ggggeg')
try:
    # Use tensorflow-cpu if available
    try:
        print('frfrfrf')
        import tensorflow as tf
        print("Using tensorflow-cpu package")
    except ImportError:
        print('LOL')
        import tensorflow as tf
        print(f"Using standard tensorflow package (version {tf.__version__})")
    
    # Import keras and layers
    from tensorflow_cpu import keras
    from keras import layers
    TF_AVAILABLE = True
except ImportError as e:
    print(f"ImportError: {e}")
    print("Warning: TensorFlow/Keras not installed. CNN-based classification will be disabled.")
    print("Install with: pip install tensorflow-cpu")
    TF_AVAILABLE = False
except Exception as e:
    print(f"Error initializing TensorFlow: {e}")
    TF_AVAILABLE = False

# Import script module last to avoid circular imports
print("Importing script module...")
try:
    import script
    print("Successfully imported script module")
except Exception as e:
    print(f"Error importing script module: {e}")
    sys.exit(1)

def prepare_image_dataset():
    """Prepare image dataset for CNN training"""
    # Create image dataset from directory
    training_dataset, val_dataset = keras.utils.image_dataset_from_directory(
        script.IMG_TRAIN_DIR,
        validation_split=0.2,
        subset='both',
        seed=42,
        image_size=(script.IMG_SIZE, script.IMG_SIZE),
        batch_size=script.BATCH_SIZE,
        label_mode='categorical',
        color_mode='grayscale'
    )
    
    # Apply data augmentation
    augmented_training_dataset = training_dataset.map(
        lambda img, label: (data_augmentation(img), label)
    )
    
    return augmented_training_dataset, val_dataset

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
        byte_data = np.zeros(script.IMG_SIZE * script.IMG_SIZE, dtype=np.uint8) 

    padded_data = np.zeros(script.IMG_SIZE * script.IMG_SIZE, dtype=np.uint8)
    padded_data[:min(len(byte_data), script.IMG_SIZE * script.IMG_SIZE)] = byte_data[:script.IMG_SIZE * script.IMG_SIZE]
    img_array = padded_data.reshape((script.IMG_SIZE, script.IMG_SIZE))
    img = Image.fromarray(img_array, mode='L')
    
    # Save the image if needed
    if file_name:
        if train and label:
            img.save(os.path.join(script.IMG_TRAIN_DIR, label, file_name[:9] + '.jpg'))
        elif not train:
            img.save(os.path.join(script.IMG_VAL_DIR, file_name[:9] + '.jpg'))
    
    return np.array(img)

if __name__ == "__main__":
    print('Image module compiled and working')
