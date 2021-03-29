A couple Linux backdoors:

    1. Simple SSH backdoor writen on GO
        https://github.com/NinjaJc01/ssh-backdoor

        # HASH generator for custom password
        https://www.convertstring.com/ru/Hash/SHA512
        
        # or in python
            import hashlib
            salt = '1c362db832f3f864c8c2fe05f2002a05'
            password = 'november16'
            hashlib.sha512(f'{password}{salt}'.encode("utf8")).hexdigest()
        # out example
'6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed'

    2. 