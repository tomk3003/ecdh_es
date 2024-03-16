@echo off
setlocal

if "%2" == "" goto :usage

set /p PUBLIC_KEY=<%1
perl -MCrypt::ECDH_ES -E "print unpack('H*', Crypt::ECDH_ES::ecdhes_encrypt(pack('H*', '%PUBLIC_KEY%'), '%2'))"
goto :eof

:usage
echo usage: encrypt ^<public_key_file^> ^<plaintext^>