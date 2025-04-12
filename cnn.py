import sys
import os
import numpy as np
import pandas as pd
import image
import script
import tensorflow as tf
from tensorflow import keras
from keras import layers

def train_cnn_model(epochs=10):
    """Train CNN model on image data"""
    print("Preparing image dataset...")
    augmented_training_dataset, val_dataset = image.prepare_image_dataset()
    
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
    for file in os.listdir(script.DIR):
        file_path = os.path.join(script.DIR, file)
        greyscale_img = image.create_greyscale_image(file_path, file_name=file, train=False)
        img_array = keras.utils.img_to_array(greyscale_img)
        img_array = img_array.reshape(1, script.IMG_SIZE, script.IMG_SIZE, 1)
        
        pred_probs = model.predict(img_array)
        pred_label = np.argmax(pred_probs)
        confidence = np.max(pred_probs)
        
        results.append({
            'filename': file,
            'label': script.INV_LABELS[pred_label],
            'confidence': float(confidence)
        })
    
    # Save results to CSV
    df = pd.DataFrame(results)
    df.to_csv("results/cnn_classification.csv", index=False)
    
    # Print summary
    print("\n--- CNN Classification Results ---")
    for label in script.LABELS.keys():
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
        layers.Dropout(0.5),  # Increased dropout to prevent overfitting
        layers.Dense(len(script.LABELS), activation='softmax')
    ])
    model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
    return model
