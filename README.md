# GOHSM

CLI tool to interact with SoftHSM.

Options:
+ List all objects
    + Select key for operation
        + Encryption/Decryption
        + Verify if the key could perform operation
+ Generate Key
    + Select the type of key
    + Provide the functionality
+ Encryption
    + Text input
    + File
+ Decryption
    + Text input
    + File
+ Wrapping
    + Generate new key
    + Use existing key
    + Generate key to be wrapped
    + Read in key to be wrapped
        + File
+ Sign
    + Select key for signing
    + Select algorithm for signing
    + File
+ Verify
    + Select key for verification
        + Read from file?
    + File

