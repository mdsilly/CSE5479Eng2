import sys
import os
import numpy as np
import pandas as pd
import image
import script
import tensorflow as tf
from tensorflow import keras
from keras import layers

def train_cnn_model(epochs=5, samples_per_class=50, binary = True):
    """Train CNN model on image data"""
    print("Preparing image dataset...")
    augmented_training_dataset, val_dataset = image.prepare_image_dataset(samples_per_class=samples_per_class)

    print("Building and training CNN model...")
    model = build_cnn_model_binary() if binary else build_cnn_model()
    model.fit(
        augmented_training_dataset,
        epochs=epochs,
        validation_data=val_dataset,
        callbacks=[
            keras.callbacks.EarlyStopping(patience=3, restore_best_weights=True)
        ]
    )

    # Save the model
    ext = 'binary' if binary else 'classifier'
    model_path = f'models/malware_{ext}.h5'
    model.save(model_path)
    print(f"CNN model saved as {model_path}")

    return model


def classify_samples_cnn(model=None, binary = True):
    """Classify samples using CNN model"""
    if model is None:
        try:
            model = keras.models.load_model('malware_classifier.h5')
        except:
            print("No model found. Please train the model first.")
            return None

    results = []
    for file in os.listdir(script.IMG_VAL_DIR):
        file_path = os.path.join(script.IMG_VAL_DIR, file)
        greyscale_img = script.create_greyscale_image(file_path, file_name=file, train=False)
        img_array = keras.utils.img_to_array(greyscale_img)
        img_array = img_array.reshape(1, script.IMG_SIZE, script.IMG_SIZE, 1)

        pred_probs = model.predict(img_array)
        pred_label = np.argmax(pred_probs)
        confidence = np.max(pred_probs)

        inv_labels = script.INV_BINARY_LABELS if binary else script.INV_LABELS

        results.append({
            'filename': file,
            'label': inv_labels[pred_label],
            'confidence': float(confidence)
        })

    # Save results to CSV
    df = pd.DataFrame(results)
    ext = 'binary' if binary else 'classification'
    path = f"results/cnn_{ext}.csv"
    df.to_csv(path, index=False)

    # Print summary
    print("\n--- CNN Classification Results ---")
    labels = script.BINARY_LABELS if binary else script.LABELS
    for label in labels.keys():
        count = sum(1 for r in results if r['label'] == label)
        print(f"{label}: {count} samples ({count/len(results)*100:.2f}%)")

    return results

def build_cnn_model():
    """Build a CNN model for image-based classification"""
    model = keras.Sequential([
        layers.Input(shape=(script.IMG_SIZE, script.IMG_SIZE, 1)),  # Ensure consistent input image sizes
        layers.Rescaling(1.0/255),
        layers.Conv2D(32, (3, 3), activation='relu', input_shape=(script.IMG_SIZE, script.IMG_SIZE, 1)),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu'),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu'),
        layers.MaxPooling2D((2, 2)),
        layers.Flatten(),
        layers.Dense(128, activation='relu'),
        layers.Dropout(0.35),  # Increased dropout to prevent overfitting
        layers.Dense(len(script.LABELS), activation='softmax')
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model

def build_cnn_model_binary():
    """Build a CNN model for image-based classification"""
    model = keras.Sequential([
        layers.Input(shape=(script.IMG_SIZE, script.IMG_SIZE, 1)),  # Ensure consistent input image sizes
        layers.Rescaling(1.0/255),
        layers.Conv2D(32, (3, 3), activation='relu', input_shape=(script.IMG_SIZE, script.IMG_SIZE, 1)),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu'),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu'),
        layers.MaxPooling2D((2, 2)),
        layers.Flatten(),
        layers.Dense(128, activation='relu'),
        layers.Dropout(0.35),  # Increased dropout to prevent overfitting
        layers.Dense(len(script.BINARY_LABELS), activation='softmax')
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model
