<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Document</title>
</head>
<body>

test

<script src="/js/vendor/aes.js"></script>

<script>
    // on entering a vault, check for existence of a vault password (stored in sessionStorage using the UUID as the key)

    var name = sessionStorage.getItem("baz");

    console.log(name);
    //sessionStorage.setItem("foobar", "passphrase");
    // if not set, request it


    // request verified against the control lockbox for the vault


    var encrypted = CryptoJS.AES.encrypt("phil@iseekplant.com.au", "passphrase");

    var str = encrypted.toString();


    console.log(str);

    str = 'U2FsdGVkX18GDph28pdSpJfWUE6nZeMd6SbIkgEzrT7es2vGyYkmPZmXl3oglS21';


    var decrypted = CryptoJS.AES.decrypt(str, "passphrase");

    if(decrypted.toString(CryptoJS.enc.Latin1))
    {
        console.log('success');
    }
    //console.log(decrypted.toString(CryptoJS.enc.Latin1));
</script>

</body>
</html>