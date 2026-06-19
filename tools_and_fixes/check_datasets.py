"""
GenAI Security Gateway - Check Datasets Yardımcı Aracı

Bu araç 'check_datasets.py', geliştirme sürecinde verileri analiz etmek, logları incelemek
veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.
"""
# pyrefly: ignore [missing-import]
import httpx

datasets = [
  'hackaprompt/hackaprompt-dataset',
  'jackhhao/jailbreak-prompts',
  'rubendura/prompt-injection-dataset',
  'lakera/prompt_injections',
  'JasperLS/jailbreak-dataset',
  'notrichardren/jailbreak-prompts'
]

for ds in datasets:
    try:
        url = f"https://datasets-server.huggingface.co/rows?dataset={ds.replace('/', '%2F')}&config=default&split=train&offset=0&length=1"
        res = httpx.get(url, timeout=5)
        print(f"{ds}: {res.status_code}")
    except Exception as e:
        print(f"{ds}: HATA -> {e}")
