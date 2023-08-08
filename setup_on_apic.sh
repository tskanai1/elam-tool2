echo '### Setup elam-tool2 on APIC ...'
echo '### Installing pexpect-4.8.0 ...'
tar zxf ./packages/pexpect-4.8.0.tar.gz -C ./packages/
cd ./packages/pexpect-4.8.0/
python3 ./setup.py install --user
cd ../../
echo '### Installing ptyprocess-0.7.0 ...'
tar zxf ./packages/ptyprocess-0.7.0.tar.gz -C ./packages/
cd ./packages/ptyprocess-0.7.0/
python3 ./setup.py install --user
cd ../../
echo '### Installed packages are:'
ls  ~/.local/lib/python3.7/site-packages/
echo '### Setup is completed!'
