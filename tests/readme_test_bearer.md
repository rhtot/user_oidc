= Strategy to test bearer API feature

Nextcloud token original call:
```
curl -i -u "120049010000000007210207:magse-Qi8Ho-jDyox-ydbxN-sHp6C" -X GET 'https://dev2.next.magentacloud.de/ocs/v1.php/cloud/users/120049010000000007210207' -H "OCS-APIRequest: true" -H 'Content-Type: application/json' -H 'Accept: application/json'
```

Bearer token call:
```
curl -i -H "OCS-APIRequest: true" -H "Authorisation: Bearer " -X GET 'https://dev2.next.magentacloud.de/ocs/v1.php/cloud/users/120049010000000007210207/' 
```
