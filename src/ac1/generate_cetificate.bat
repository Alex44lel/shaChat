@echo off
:: Prompt for user ID if not provided as an argument
if "%~1"=="" (
    echo Usage: generate_cert.bat [User ID] [Client folder]
    exit /b
)

if "%~2"=="" (
    echo Usage: generate_cert.bat [User ID] [Client folder]
    exit /b
)

:: Assign the argument to a variable
set USER_ID=%~1
set CLIENT_FOLDER=%~2

:: Step 8: Verify the request "sent" by A
echo Verifying the certificate request for User ID %USER_ID%
openssl req -in ./solicitudes/csr_%USER_ID%.pem -text -noout

:: Step 9: Generate the certificate for A
echo Generating the certificate for User ID %USER_ID%
openssl ca -in ./solicitudes/csr_%USER_ID%.pem -out ./nuevoscerts/cert_%USER_ID%.pem -notext -config ./openssl_AC1.cnf

echo copying
copy ".\nuevoscerts\cert_%USER_ID%.pem" "..\%CLIENT_FOLDER%\cert_%USER_ID%.pem"

:: Step 10
echo Verifying the resulting certificate for User ID %USER_ID%
openssl x509 -in ./nuevoscerts/cert_%USER_ID%.pem -text -noout

echo end of script
