import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    confusion_matrix, classification_report, 
    roc_curve, auc, precision_recall_curve, average_precision_score
)
from sklearn.preprocessing import label_binarize
from sklearn.calibration import calibration_curve
import matplotlib as mpl

# Set the style for better-looking plots
plt.style.use('seaborn-v0_8-darkgrid')
mpl.rcParams['figure.figsize'] = (12, 8)
mpl.rcParams['axes.grid'] = True
mpl.rcParams['font.size'] = 12

class ModelVisualizer:
    def __init__(self, model_path, output_dir='model_visualizations'):
        """
        Initialize the ModelVisualizer with a trained model and output directory.
        
        Args:
            model_path (str): Path to the saved model pipeline
            output_dir (str): Directory to save visualizations
        """
        self.model = joblib.load(model_path)
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set class names based on your model's classes
        self.classes = ['Normal', 'SQL Injection', 'XSS']
        self.n_classes = len(self.classes)
    
    def load_data(self, data_path):
        """Load and preprocess the dataset."""
        # Load the dataset
        self.data = pd.read_csv(data_path)
        
        # Drop rows with NaN values in 'Query' or 'Label' columns
        self.data = self.data.dropna(subset=['Query', 'Label'])
        
        # Ensure Label is integer type
        self.data['Label'] = self.data['Label'].astype(int)
        
        # Handle any empty strings in Query
        self.data = self.data[self.data['Query'].astype(str).str.strip() != '']
        
        # Extract features and target
        self.X = self.data['Query'].astype(str)  # Ensure all queries are strings
        self.y = self.data['Label']
        
        print(f"Loaded {len(self.X)} samples")
        print("Class distribution:")
        print(self.y.value_counts())
        
        # Make predictions
        try:
            self.y_pred = self.model.predict(self.X)
            self.y_pred_proba = self.model.predict_proba(self.X)
            
            # Binarize the output for ROC and PR curves
            self.y_bin = label_binarize(self.y, classes=range(self.n_classes))
            
            return self.X, self.y, self.y_pred
            
        except Exception as e:
            print(f"Error during prediction: {str(e)}")
            print("Sample of problematic data:")
            print(self.X.head())
            raise
    
    def plot_confusion_matrix(self):
        """Plot and save a normalized confusion matrix."""
        cm = confusion_matrix(self.y, self.y_pred)
        cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(
            cm_normalized, 
            annot=True, 
            fmt='.2f', 
            cmap='Blues',
            xticklabels=self.classes,
            yticklabels=self.classes
        )
        plt.title('Normalized Confusion Matrix')
        plt.xlabel('Predicted Label')
        plt.ylabel('True Label')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'confusion_matrix.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_roc_curves(self):
        """Plot ROC curves for each class and micro/macro averages."""
        # Compute ROC curve and ROC area for each class
        fpr = dict()
        tpr = dict()
        roc_auc = dict()
        
        for i in range(self.n_classes):
            fpr[i], tpr[i], _ = roc_curve(self.y_bin[:, i], self.y_pred_proba[:, i])
            roc_auc[i] = auc(fpr[i], tpr[i])
        
        # Compute micro-average ROC curve and ROC area
        fpr["micro"], tpr["micro"], _ = roc_curve(self.y_bin.ravel(), self.y_pred_proba.ravel())
        roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])
        
        # Plot all ROC curves
        plt.figure(figsize=(10, 8))
        
        # Plot each class
        for i, class_name in enumerate(self.classes):
            plt.plot(fpr[i], tpr[i], lw=2,
                     label=f'ROC curve of {class_name} (area = {roc_auc[i]:.2f})')
        
        # Plot micro-average
        plt.plot(fpr["micro"], tpr["micro"],
                 label=f'micro-average ROC (area = {roc_auc["micro"]:.2f})',
                 color='deeppink', linestyle=':', linewidth=4)
        
        plt.plot([0, 1], [0, 1], 'k--', lw=2)
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curves')
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'roc_curves.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_precision_recall_curves(self):
        """Plot precision-recall curves for each class."""
        precision = dict()
        recall = dict()
        average_precision = dict()
        
        for i in range(self.n_classes):
            precision[i], recall[i], _ = precision_recall_curve(
                self.y_bin[:, i], self.y_pred_proba[:, i])
            average_precision[i] = average_precision_score(
                self.y_bin[:, i], self.y_pred_proba[:, i])
        
        # Compute micro-average PR curve and PR area
        precision["micro"], recall["micro"], _ = precision_recall_curve(
            self.y_bin.ravel(), self.y_pred_proba.ravel())
        average_precision["micro"] = average_precision_score(
            self.y_bin, self.y_pred_proba, average="micro")
        
        # Plot PR curves
        plt.figure(figsize=(10, 8))
        
        for i, class_name in enumerate(self.classes):
            plt.plot(recall[i], precision[i], lw=2,
                     label=f'Precision-Recall curve of {class_name} (AP = {average_precision[i]:.2f})')
        
        # Plot micro-average
        plt.plot(recall["micro"], precision["micro"],
                 label=f'micro-average Precision-Recall (AP = {average_precision["micro"]:.2f})',
                 color='gold', linestyle=':', linewidth=4)
        
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curves')
        plt.legend(loc="lower left")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'precision_recall_curves.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_feature_importance(self, top_n=20):
        """Plot feature importance if the model supports it."""
        if hasattr(self.model.named_steps['classifier'], 'feature_importances_'):
            feature_importances = self.model.named_steps['classifier'].feature_importances_
            feature_names = self.model.named_steps['vectorizer'].get_feature_names_out()
            
            # Sort feature importances in descending order
            indices = np.argsort(feature_importances)[::-1]
            
            # Get top N features
            top_indices = indices[:top_n]
            top_features = [feature_names[i] for i in top_indices]
            top_importances = feature_importances[top_indices]
            
            # Plot
            plt.figure(figsize=(12, 8))
            sns.barplot(x=top_importances, y=top_features, palette='viridis')
            plt.title(f'Top {top_n} Most Important Features')
            plt.xlabel('Feature Importance Score')
            plt.ylabel('Features')
            plt.tight_layout()
            plt.savefig(os.path.join(self.output_dir, 'feature_importance.png'), dpi=300, bbox_inches='tight')
            plt.close()
    
    def plot_calibration_curves(self):
        """Plot calibration curves for each class."""
        plt.figure(figsize=(10, 8))
        plt.plot([0, 1], [0, 1], 'k--', label='Perfectly calibrated')
        
        for i, class_name in enumerate(self.classes):
            prob_true, prob_pred = calibration_curve(
                self.y_bin[:, i], 
                self.y_pred_proba[:, i], 
                n_bins=10,
                strategy='quantile'
            )
            plt.plot(prob_pred, prob_true, 's-', label=f'{class_name}')
        
        plt.xlabel('Mean predicted probability')
        plt.ylabel('Fraction of positives')
        plt.title('Calibration Curves (Reliability Curves)')
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'calibration_curves.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_class_distribution(self):
        """Plot the distribution of classes in the dataset."""
        class_counts = pd.Series(self.y).value_counts().sort_index()
        class_names = [self.classes[i] for i in class_counts.index]
        
        plt.figure(figsize=(10, 6))
        sns.barplot(x=class_names, y=class_counts.values, palette='Set2')
        plt.title('Class Distribution in Dataset')
        plt.xlabel('Class')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, 'class_distribution.png'), dpi=300, bbox_inches='tight')
        plt.close()
    
    def generate_all_visualizations(self, data_path):
        """Generate all visualizations."""
        print("Loading data and making predictions...")
        self.load_data(data_path)
        
        print("Generating visualizations...")
        self.plot_confusion_matrix()
        print("✓ Confusion matrix saved")
        
        self.plot_roc_curves()
        print("✓ ROC curves saved")
        
        self.plot_precision_recall_curves()
        print("✓ Precision-Recall curves saved")
        
        self.plot_feature_importance()
        print("✓ Feature importance plot saved")
        
        self.plot_calibration_curves()
        
        print("✓ Calibration curves saved")
        
        self.plot_class_distribution()
        print("✓ Class distribution plot saved")
        
        print(f"\nAll visualizations have been saved to: {os.path.abspath(self.output_dir)}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate model visualization and analysis.')
    parser.add_argument('--model', type=str, default='security_model_pipeline.pkl',
                       help='Path to the trained model pipeline')
    parser.add_argument('--data', type=str, required=True,
                       help='Path to the dataset CSV file')
    parser.add_argument('--output', type=str, default='model_visualizations',
                       help='Output directory for visualizations')
    
    args = parser.parse_args()
    
    # Initialize the visualizer
    visualizer = ModelVisualizer(args.model, args.output)
    
    # Generate all visualizations
    visualizer.generate_all_visualizations(args.data)
