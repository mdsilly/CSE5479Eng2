import sys
import os
import numpy as np
import random
import shutil
import tempfile
from PIL import Image
import tensorflow as tf
from tensorflow import keras
from keras import layers

# Import script module last to avoid circular imports
print("Importing script module...")
try:
    import script
    print("Successfully imported script module")
except Exception as e:
    print(f"Error importing script module: {e}")
    sys.exit(1)

def sample_images_from_classes(source_dir, samples_per_class):
    """
    Sample n images from each class directory.
    
    Args:
        source_dir: Path to the directory containing class subdirectories
        samples_per_class: Number of samples to select from each class
        
    Returns:
        Path to a temporary directory containing the sampled images
    """
    print(f"Sampling {samples_per_class} images from each class in {source_dir}...")
    
    # Create a temporary directory to store the sampled images
    temp_dir = tempfile.mkdtemp(prefix="sampled_images_")
    
    # Get all class directories
    class_dirs = [d for d in os.listdir(source_dir) if os.path.isdir(os.path.join(source_dir, d))]
    print(f"Found {len(class_dirs)} class directories: {class_dirs}")
    
    for class_dir in class_dirs:
        class_path = os.path.join(source_dir, class_dir)
        
        # Create corresponding directory in the temporary directory
        temp_class_dir = os.path.join(temp_dir, class_dir)
        os.makedirs(temp_class_dir, exist_ok=True)
        
        # Get all image files in the class directory
        image_files = [f for f in os.listdir(class_path) if os.path.isfile(os.path.join(class_path, f)) and 
                      f.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp'))]
        
        # If the class directory has subdirectories (like malicious/family), handle them
        if len(image_files) == 0:
            subclass_dirs = [d for d in os.listdir(class_path) if os.path.isdir(os.path.join(class_path, d))]
            for subclass_dir in subclass_dirs:
                subclass_path = os.path.join(class_path, subclass_dir)
                temp_subclass_dir = os.path.join(temp_class_dir, subclass_dir)
                os.makedirs(temp_subclass_dir, exist_ok=True)
                
                # Get all image files in the subclass directory
                subclass_image_files = [f for f in os.listdir(subclass_path) if os.path.isfile(os.path.join(subclass_path, f)) and 
                                      f.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp'))]
                
                # Sample images from the subclass
                sampled_files = subclass_image_files
                if len(subclass_image_files) > samples_per_class:
                    sampled_files = random.sample(subclass_image_files, samples_per_class)
                
                print(f"  Sampled {len(sampled_files)}/{len(subclass_image_files)} images from {class_dir}/{subclass_dir}")
                
                # Copy sampled images to the temporary directory
                for image_file in sampled_files:
                    src_path = os.path.join(subclass_path, image_file)
                    dst_path = os.path.join(temp_subclass_dir, image_file)
                    shutil.copy2(src_path, dst_path)
        else:
            # Sample images from the class
            sampled_files = image_files
            if len(image_files) > samples_per_class:
                sampled_files = random.sample(image_files, samples_per_class)
            
            print(f"  Sampled {len(sampled_files)}/{len(image_files)} images from {class_dir}")
            
            # Copy sampled images to the temporary directory
            for image_file in sampled_files:
                src_path = os.path.join(class_path, image_file)
                dst_path = os.path.join(temp_class_dir, image_file)
                shutil.copy2(src_path, dst_path)
    
    return temp_dir

def prepare_image_dataset(samples_per_class=50, binary=True, label_mode=None):
    """Prepare image dataset for CNN training"""
    # Sample images from each class if samples_per_class is specified
    if samples_per_class is not None and samples_per_class > 0:
        # Create a temporary directory with sampled images
        temp_dir = sample_images_from_classes(script.IMG_TRAIN_DIR, samples_per_class)
        source_dir = temp_dir
    else:
        # Use all available images
        source_dir = script.IMG_TRAIN_DIR
    
    # Use provided label_mode or default to binary/categorical based on binary parameter
    if label_mode is None:
        label_mode = 'binary' if binary else 'categorical'
    
    # Create image dataset from directory
    training_dataset = keras.utils.image_dataset_from_directory(
        source_dir,
        validation_split=0.2,
        subset='training',
        seed=42,
        image_size=(script.IMG_SIZE, script.IMG_SIZE),
        batch_size=script.BATCH_SIZE,
        label_mode=label_mode,
        color_mode='grayscale'
    )

    # Create image dataset from directory
    val_dataset = keras.utils.image_dataset_from_directory(
        source_dir,
        validation_split=0.2,
        subset='validation',
        seed=42,
        image_size=(script.IMG_SIZE, script.IMG_SIZE),
        batch_size=script.BATCH_SIZE,
        label_mode=label_mode,
        color_mode='grayscale'
    )
    
    # Clean up the temporary directory if we created one
    if samples_per_class is not None and samples_per_class > 0:
        print(f"Cleaning up temporary directory: {temp_dir}")
        # Comment out the cleanup for debugging if needed
        # shutil.rmtree(temp_dir)


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
        layers.GaussianNoise(0.01)
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
