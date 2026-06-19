"""
GenAI Security Gateway - Fix Logs Yardımcı Aracı

Bu araç 'fix_logs.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
import sqlite3
import json
import re

conn = sqlite3.connect(r'C:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\genai_gateway.db')
c = conn.cursor()

# Önce corrections_needed.json'u oku
with open(r'C:\Users\user\Downloads\GenAI_GateAway-main\GenAI_GateAway-main\corrections_needed.json') as f:
    corrections = json.load(f)

print(f"Fixing {len(corrections)} incorrect logs...\n")

fixed_count = 0
for corr in corrections:
    log_id = corr['log_id']
    new_category = corr['correct_category']
    new_action = corr['correct_action']
    
    # Veritabanında güncelle
    c.execute("""
        UPDATE security_logs 
        SET category = ?, action = ?
        WHERE log_id = ?
    """, (new_category, new_action, log_id))
    
    fixed_count += 1
    if fixed_count % 10 == 0:
        print(f"Fixed {fixed_count}/{len(corrections)}...")

conn.commit()
print(f"\n✓ All {fixed_count} logs corrected!")

# Doğrulama - tekrar kontrol
from analyze_logs import categorize_log, should_block
c.execute("SELECT log_id, masked_prompt, category, action FROM security_logs")
logs = c.fetchall()

verification_errors = 0
for log_id, text, db_category, db_action in logs:
    correct_category = categorize_log(text)
    expected_action = "BLOCK" if should_block(correct_category) else "ALLOW"
    
    if db_category != correct_category or db_action != expected_action:
        verification_errors += 1

conn.close()

print(f"\nVerification: {len(logs) - verification_errors}/{len(logs)} logs correct")
print(f"Error rate: {verification_errors/len(logs)*100:.1f}%")

if verification_errors == 0:
    print("\n SUCCESS! All logs are now correctly categorized!")
