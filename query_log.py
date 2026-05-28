import sqlite3
import sys
pid_prefix = sys.argv[1] if len(sys.argv)>1 else '8da1cb8a'
conn=sqlite3.connect('genai_gateway.db')
c=conn.cursor()
c.execute("SELECT log_id, masked_prompt, action, category, stopped_at_layer, created_at FROM security_logs WHERE log_id LIKE ?", (pid_prefix+'%',))
rows=c.fetchall()
if not rows:
    print('Log bulunamadi:', pid_prefix)
else:
    for r in rows:
        print('ID:', r[0])
        print('Text:', r[1])
        print('Action:', r[2])
        print('Category:', r[3])
        print('Stopped at:', r[4])
        print('Time:', r[5])
        print()
conn.close()
