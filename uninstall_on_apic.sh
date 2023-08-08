echo '### Uninstall elam-tool2 on APIC ...'
echo '### Uninstalling pexpect-4.8.0 ...'
cd ./packages/pexpect-4.8.0/
python3 ./setup.py install --user --record pexpect_list.txt
cat pexpect_list.txt | xargs rm -rf
rm -r ~/.local/lib/python3.7/site-packages/pexpect
cd ../../
echo '### Uninstalling ptyprocess-0.7.0 ...'
cd ./packages/ptyprocess-0.7.0/
python3 ./setup.py install --user --record ptyprocess_list.txt
cat ptyprocess_list.txt | xargs rm -rf
rm -r ~/.local/lib/python3.7/site-packages/ptyprocess
cd "${HOME}"
echo '### Remove elam-tool2 directory'
rm -r ~/elam-tool2-master
echo '### No packages should be here:'
ls  ~/.local/lib/python3.7/site-packages/
echo '### Uninstall elam-tool2 is completed!'
