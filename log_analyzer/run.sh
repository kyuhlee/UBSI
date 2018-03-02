sudo killall -9 auditd
sudo mv /var/log/audit/audit.log ./
sudo chown audit ./audit.log
../auditlog_tool/sortlog ./audit.log ./audit_sort.log 
./bt_beep ./audit_sort.log inode=$1

