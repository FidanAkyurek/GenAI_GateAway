import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
original_script_path = os.path.join(BASE_DIR, "scripts", "train_deberta.py")

with open(original_script_path, "r", encoding="utf-8") as f:
    content = f.read()

# Anti-freeze modifications
content = content.replace("per_device_train_batch_size=8", "per_device_train_batch_size=2,\n        gradient_accumulation_steps=4")
content = content.replace("per_device_eval_batch_size=8", "per_device_eval_batch_size=2")

# Add overwrite_output_dir=True
content = content.replace("output_dir=MODEL_OUTPUT_DIR,", "output_dir=MODEL_OUTPUT_DIR,\n        overwrite_output_dir=True,")

for i in range(1, 5):
    new_content = content.replace("custom_dataset_full.csv", f"custom_dataset_part{i}.csv")
    
    if i > 1:
        # After part 1, base model is the fine tuned model
        new_content = new_content.replace(
            'BASE_MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"',
            'BASE_MODEL_NAME = MODEL_OUTPUT_DIR'
        )
        
    out_path = os.path.join(BASE_DIR, "scripts", f"train_part{i}.py")
    with open(out_path, "w", encoding="utf-8") as out_f:
        out_f.write(new_content)
    print(f"Created {out_path}")
