import os
import pandas as pd
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "custom_dataset_full.csv")

def split_dataset():
    if not os.path.exists(DATA_PATH):
        print(f"Dataset bulunamadı: {DATA_PATH}")
        return
        
    df = pd.read_csv(DATA_PATH)
    total_len = len(df)
    print(f"Toplam veri sayısı: {total_len}")
    
    # 4 parçaya bölmek için
    num_parts = 4
    chunk_size = int(np.ceil(total_len / num_parts))
    
    for i in range(num_parts):
        start_idx = i * chunk_size
        end_idx = min((i + 1) * chunk_size, total_len)
        
        chunk_df = df.iloc[start_idx:end_idx]
        output_path = os.path.join(BASE_DIR, "data", f"custom_dataset_part{i+1}.csv")
        chunk_df.to_csv(output_path, index=False)
        print(f"Bölüm {i+1} oluşturuldu: {output_path} ({len(chunk_df)} satır)")

if __name__ == "__main__":
    split_dataset()
