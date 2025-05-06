# tpm_parser
Parsing profond d'un flux de commandes et réponses TPM 1.2, pour analyse.

Utilisable en outil CLI ou comme bibliothèque Python.

Commandes supportées : 1/123. Les commandes encore non-supportées sont identifiées et n'arrêtent pas le parsing des commandes suivantes ; leur `body` est un bytestream en lieu de la structure correspondante.

Exemple :
![Screenshot](images/tpm_parser_example.png)
