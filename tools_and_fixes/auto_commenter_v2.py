import os

def get_docstring(directory, filename, content):
    if "GenAI Security Gateway" in content[:500] or '"""\nGenAI' in content[:500] or "Bu test dosyası" in content[:500]:
        return None # Zaten yorum satırı var
        
    doc = '"""\n'
    
    if directory == "test_scripts":
        name = filename.replace(".py", "").replace("_", " ").title()
        doc += f"GenAI Security Gateway - {name} Test Betiği\n\n"
        doc += f"Bu test dosyası '{filename}', sistemin belirli bir bileşenini test etmek amacıyla oluşturulmuştur.\n"
        doc += "Genel amacı ilgili uç noktaların (endpoint) veya fonksiyonların doğru çalışıp çalışmadığını doğrulamaktır.\n"
        
    elif directory == "database_scripts":
        name = filename.replace(".py", "").replace("_", " ").title()
        doc += f"GenAI Security Gateway - {name} Veritabanı Betiği\n\n"
        doc += f"Bu betik '{filename}', veritabanı (PostgreSQL veya SQLite) üzerinde şema güncellemeleri,\n"
        doc += "kurulum veya veri onarımı gibi yönetimsel işlemleri gerçekleştirmek için kullanılır.\n"
        
    elif directory == "tools_and_fixes":
        name = filename.replace(".py", "").replace("_", " ").title()
        doc += f"GenAI Security Gateway - {name} Yardımcı Aracı\n\n"
        doc += f"Bu araç '{filename}', geliştirme sürecinde verileri analiz etmek, logları incelemek\n"
        doc += "veya sistemdeki hataları ayıklamak (debug) amacıyla yazılmış yardımcı bir betiktir.\n"
        
    else:
        return None
        
    doc += '"""\n'
    return doc

def process_directory(directory):
    if not os.path.exists(directory):
        return
        
    for filename in os.listdir(directory):
        if filename.endswith(".py"):
            filepath = os.path.join(directory, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                
            doc = get_docstring(directory, filename, content)
            if doc:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(doc + content)
                print(f"Commented: {filepath}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(base_dir)
    
    process_directory("test_scripts")
    process_directory("database_scripts")
    process_directory("tools_and_fixes")
    print("Toplu yorum ekleme islemi tamamlandi.")
