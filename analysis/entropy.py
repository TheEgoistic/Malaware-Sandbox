import math
from collections import Counter

def calculate_file_entropy(file_path):
    """Calculate the Shannon entropy of a file."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return 0.0

        file_size = len(data)
        byte_counts = Counter(data)
        
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / file_size
            entropy -= probability * math.log2(probability)
            
        return round(entropy, 2)
    except Exception as e:
        print(f"Error calculating entropy: {e}")
        return -1.0
