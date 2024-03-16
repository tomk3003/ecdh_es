@echo off
setlocal

if "%2" == "" goto :usage

set /p PRIVATE_KEY=<%1
perl -MCrypt::ECDH_ES -E "print Crypt::ECDH_ES::ecdhes_decrypt(pack('H*', '%PRIVATE_KEY%'), pack('H*', '%2'))"
goto :eof

:usage
echo usage: decrypt ^<private_key_file^> ^<crypted_hex^>