import pandas as pd
import numpy as np
import pickle
import os
import time
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.pipeline import Pipeline
import joblib

print("Starting model training...")
start_time = time.time()

# Load dataset
print("\nLoading dataset...")
data_path = r'C:\Users\DELL\Desktop\Grad codes\Model\Datasets\combined_data.csv'
data = pd.read_csv(data_path)
print(f"Dataset shape: {data.shape}")
print(f"Label distribution:\n{data['Label'].value_counts()}")

# Clean and preprocess the data
print("\nPreprocessing data...")
# Handle missing values if any
data['Query'].fillna('', inplace=True)

# Split into features and target
X = data['Query']
y = data['Label']

# Split into training and test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Training set size: {X_train.shape[0]}")
print(f"Test set size: {X_test.shape[0]}")

# Create a pipeline with TF-IDF vectorizer and RandomForest classifier
print("\nCreating and training the model pipeline...")
pipeline = Pipeline([
    ('vectorizer', TfidfVectorizer(
        max_features=5000,  # Limit features to prevent overfitting
        min_df=2,           # Minimum document frequency
        ngram_range=(1, 2), # Use both unigrams and bigrams
        sublinear_tf=True,  # Apply sublinear tf scaling (logarithmic)
        strip_accents='unicode',  # Remove accents
        lowercase=True      # Convert to lowercase
    )),
    ('classifier', RandomForestClassifier(
        n_estimators=100,   # Number of trees
        max_depth=None,     # Maximum depth of trees
        min_samples_split=2,
        min_samples_leaf=1,
        max_features='sqrt',
        n_jobs=-1,          # Use all available cores
        random_state=42,
        class_weight='balanced'  # Handle class imbalance
    ))
])

# Train the pipeline
print("Training the model...")
pipeline.fit(X_train, y_train)

# Evaluate the model
print("\nEvaluating the model...")
y_pred = pipeline.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}")

# Detailed classification report
print("\nClassification report:")
target_names = ['Normal', 'SQL Injection', 'XSS']
print(classification_report(y_test, y_pred, target_names=target_names))

# Confusion matrix
print("\nConfusion matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# Save the pipeline (both vectorizer and model)
print("\nSaving the model pipeline...")
model_path = r'security_model_pipeline.pkl'
joblib.dump(pipeline, model_path)
print(f"Model pipeline saved to {os.path.abspath(model_path)}")

# Test the saved model on some examples
print("\nTesting the saved model on examples...")
examples = [
    "Hello world",                              # Normal
    "' OR 1=1 --",                            # SQL injection
    "<script>alert('XSS')</script>",           # XSS
    "admin'; DROP TABLE users; --",            # SQL injection
    "<img src=x onerror=alert(1)>",           # XSS
    "Buy groceries tomorrow",                  # Normal
    "SELECT * FROM users WHERE username = 'admin'",  # SQL injection
    "<a href='javascript:alert(1)'>Click me</a>",    # XSS
]

# Load the model back to verify it works
loaded_pipeline = joblib.load(model_path)

# Test examples
print("\nPrediction results:")
for text in examples:
    prediction = loaded_pipeline.predict([text])[0]
    result = {
        0: "NORMAL",
        1: "SQL_INJECTION",
        2: "XSS"
    }.get(prediction, "UNKNOWN")
    
    print(f"Input: {text}")
    print(f"Prediction: {prediction} ({result})\n")

# Calculate training time
end_time = time.time()
training_time = end_time - start_time
print(f"\nTotal training and evaluation time: {training_time:.2f} seconds")
print("Model training completed successfully!")
