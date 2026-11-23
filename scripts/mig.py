import subprocess
target = 'x'
subprocess.run(['flask', 'db', 'upgrade', target])
