@echo off
echo ========================================================
echo GenAI Security Gateway Baslatiliyor...
echo (Ana Python ortami kullaniliyor)
echo ========================================================
C:\Users\fidan\anaconda3\python.exe -m uvicorn app.main:app --reload --port 8001
pause
